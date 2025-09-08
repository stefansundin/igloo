use std::{
  env,
  sync::{Arc, OnceLock},
};

use rustls::{
  server::{ClientHello, ResolvesServerCert},
  sign,
};

use crate::{cert::certificate_data_lock, utils};

fn require_sni() -> &'static bool {
  static DATA: OnceLock<bool> = OnceLock::new();
  DATA.get_or_init(|| {
    let require_sni = env::var("REQUIRE_SNI").unwrap_or("true".to_string());
    require_sni == "true"
  })
}

#[derive(Debug)]
pub struct CertResolver {}

impl ResolvesServerCert for CertResolver {
  fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
    match *certificate_data_lock().read().unwrap() {
      None => None,
      Some(ref certificate_data) => {
        if *require_sni() && !utils::includes_host(&client_hello.server_name(), &certificate_data.names.iter().map(String::as_str).collect()) {
          return None;
        }

        Some(certificate_data.certified_key.clone())
      }
    }
  }
}
