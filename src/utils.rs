use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use std::{
  env, fs,
  io::{BufReader, Cursor, Error, ErrorKind, Read, Result, Seek},
  sync::Arc,
};
use tokio_rustls::TlsAcceptor;
use zip::ZipArchive;

fn extract_cert_and_key<R: Read + Seek>(
  zip_reader: R,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let mut certs: Option<Vec<CertificateDer<'static>>> = None;
  let mut key: Option<PrivateKeyDer<'static>> = None;
  let mut archive = ZipArchive::new(zip_reader)?;

  for i in 0..archive.len() {
    let mut file = archive.by_index(i)?;
    let name = file.name().to_string();
    if name.starts_with("__MACOSX/") || !name.ends_with(".pem") {
      continue;
    }

    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;
    let mut file_reader = BufReader::new(file_data.as_slice());

    if name.starts_with("privkey") {
      key = Some(rustls_pemfile::private_key(&mut file_reader).map(|key| key.unwrap())?);
    } else if name.starts_with("fullchain") {
      certs =
        Some(rustls_pemfile::certs(&mut file_reader).collect::<Result<Vec<CertificateDer>>>()?);
    }
    if certs.is_some() && key.is_some() {
      break;
    }
  }

  if certs.is_none() || key.is_none() {
    return Err(Error::new(
      ErrorKind::Other,
      "fullchain.pem or privkey.pem not found in zip file",
    ));
  }

  return Ok((certs.unwrap(), key.unwrap()));
}

pub async fn get_tls_acceptor() -> Result<TlsAcceptor> {
  let certs: Vec<CertificateDer<'_>>;
  let key: PrivateKeyDer<'_>;

  if let Ok(certificate_url) = env::var("CERTIFICATE_URL") {
    println!("Downloading certificate bundle from {}", certificate_url);
    let response = reqwest::get(certificate_url)
      .await
      .expect("error downloading CERTIFICATE_URL");
    let response_body = response
      .bytes()
      .await
      .expect("error reading CERTIFICATE_URL");
    let cursor = Cursor::new(response_body);
    let data = extract_cert_and_key(cursor).expect("error extracting certificate files");
    certs = data.0;
    key = data.1;
  } else {
    let certificate_path = env::var("CERTIFICATE_PATH").unwrap();
    let certificate_key_path = env::var("CERTIFICATE_KEY_PATH").unwrap();

    let certfile = fs::File::open(certificate_path)?;
    let mut reader = BufReader::new(certfile);
    certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<CertificateDer>>>()?;

    let keyfile = fs::File::open(certificate_key_path)?;
    let mut reader = BufReader::new(keyfile);
    key = rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())?;
  }

  let mut server_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("error constructing server config");

  server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()];

  if env::var("USE_H2").is_ok() {
    // Warning: Make sure your upstream service supports HTTP/2
    server_config.alpn_protocols.insert(0, b"h2".to_vec());
  }

  return Ok(TlsAcceptor::from(Arc::new(server_config)));
}
