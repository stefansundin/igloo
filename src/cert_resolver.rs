use rustls::{
  server::{ClientHello, ResolvesServerCert},
  sign,
};
use std::sync::Arc;

use crate::utils;

#[derive(Debug)]
pub struct CertResolver {
  pub certified_key: Arc<sign::CertifiedKey>,
  pub cert_names: Vec<String>,
}

impl ResolvesServerCert for CertResolver {
  fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
    let server_name = client_hello.server_name();
    if !utils::includes_host(
      &server_name,
      &self.cert_names.iter().map(String::as_str).collect(),
    ) {
      return None;
    }
    Some(self.certified_key.clone())
  }
}
