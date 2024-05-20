use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use std::{
  env, fs,
  io::{BufReader, Result},
  sync::Arc,
};
use tokio_rustls::TlsAcceptor;

pub fn get_tls_acceptor() -> Result<TlsAcceptor> {
  let certificate_path = env::var("CERTIFICATE_PATH").unwrap();
  let certificate_key_path = env::var("CERTIFICATE_KEY_PATH").unwrap();

  let certfile = fs::File::open(certificate_path)?;
  let mut reader = BufReader::new(certfile);
  let certs: Vec<CertificateDer> =
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<CertificateDer>>>()?;

  let keyfile = fs::File::open(certificate_key_path)?;
  let mut reader = BufReader::new(keyfile);
  let key: PrivateKeyDer = rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())?;

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
