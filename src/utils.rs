use hyper::StatusCode;
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use std::{
  env,
  error::Error,
  fs,
  io::{self, BufReader, Cursor, Read, Seek},
  sync::{Arc, OnceLock, RwLock},
};
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::FromDer;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName};
use zip::ZipArchive;

fn etag() -> &'static RwLock<Option<String>> {
  static ETAG: OnceLock<RwLock<Option<String>>> = OnceLock::new();
  ETAG.get_or_init(|| RwLock::new(None))
}

fn extract_cert_and_key<R: Read + Seek>(
  zip_reader: R,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
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
        Some(rustls_pemfile::certs(&mut file_reader).collect::<io::Result<Vec<CertificateDer>>>()?);
    }
    if certs.is_some() && key.is_some() {
      break;
    }
  }

  if certs.is_none() || key.is_none() {
    return Err("fullchain.pem or privkey.pem not found in zip file".into());
  }

  return Ok((certs.unwrap(), key.unwrap()));
}

pub async fn get_tls_acceptor() -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
  let certs: Vec<CertificateDer<'_>>;
  let key: PrivateKeyDer<'_>;

  if let Ok(certificate_url) = env::var("CERTIFICATE_URL") {
    println!("Downloading certificate bundle from {}", certificate_url);
    let client = reqwest::Client::new();
    let mut request = client.get(certificate_url);

    {
      let etag_option = etag().read().unwrap();
      if etag_option.is_some() {
        let etag_value = etag_option.as_ref().unwrap().clone();
        request = request.header("If-None-Match", etag_value);
      }
    }

    let response = request.send().await?;
    if response.status() != StatusCode::OK {
      return Err(format!("Status code received: {}", response.status()).into());
    }
    let response_etag = response
      .headers()
      .get("ETag")
      .and_then(|v| v.to_str().ok().and_then(|v| Some(v.to_string())));

    let response_body = response.bytes().await?;
    let cursor = Cursor::new(response_body);
    let data = extract_cert_and_key(cursor)?;
    certs = data.0;
    key = data.1;

    if response_etag.is_some() {
      let mut etag_option = etag().write().unwrap();
      *etag_option = response_etag;
    }
  } else {
    let certificate_path = env::var("CERTIFICATE_PATH")?;
    let certificate_key_path = env::var("CERTIFICATE_KEY_PATH")?;

    let certfile = fs::File::open(certificate_path)?;
    let mut reader = BufReader::new(certfile);
    certs = rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<CertificateDer>>>()?;

    let keyfile = fs::File::open(certificate_key_path)?;
    let mut reader = BufReader::new(keyfile);
    key = rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())?;
  }

  let cert = X509Certificate::from_der(certs.first().unwrap())?;
  let names = cert
    .1
    .subject_alternative_name()?
    .unwrap()
    .value
    .general_names
    .iter()
    .map(|name| match name {
      GeneralName::DNSName(s) => s.to_string(),
      other => other.to_string(),
    })
    .collect::<Vec<String>>();
  eprintln!("Loading certificate for DNS names: {}", names.join(", "));
  eprintln!("Expires at: {}", cert.1.validity.not_after);

  let mut server_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;

  server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()];

  if env::var("USE_H2").is_ok() {
    // Warning: Make sure your upstream service supports HTTP/2
    server_config.alpn_protocols.insert(0, b"h2".to_vec());
  }

  return Ok(TlsAcceptor::from(Arc::new(server_config)));
}
