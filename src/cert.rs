use hyper::StatusCode;
use log::{error, info};
use rustls::{
  ServerConfig,
  crypto::aws_lc_rs,
  pki_types::{CertificateDer, PrivateKeyDer},
  sign,
};
use std::{
  env,
  error::Error,
  fs,
  io::{self, BufReader, Cursor, Read, Seek},
  sync::{Arc, OnceLock, RwLock},
  time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::OnceCell;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::FromDer;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName};
use zip::ZipArchive;

use crate::s3_url;
use crate::{cert_resolver::CertResolver, utils};

pub struct TlsData {
  pub tls_acceptor: TlsAcceptor,
  pub not_after: u64,
}

fn require_sni() -> &'static bool {
  static REQUIRE_SNI: OnceLock<bool> = OnceLock::new();
  REQUIRE_SNI.get_or_init(|| {
    let require_sni = env::var("REQUIRE_SNI").unwrap_or("true".to_string());
    require_sni == "true"
  })
}

pub async fn tls_data_lock() -> &'static RwLock<TlsData> {
  static TLS_ACCEPTOR_LOCK: OnceCell<RwLock<TlsData>> = OnceCell::const_new();
  TLS_ACCEPTOR_LOCK
    .get_or_init(|| async {
      let tls_acceptor = get_tls_data()
        .await
        .expect("Error constructing the TLS acceptor")
        .expect("Invalid response code received when retrieving certificate bundle");
      RwLock::new(tls_acceptor)
    })
    .await
}

pub async fn reload_cert(verbose: bool) {
  match get_tls_data().await {
    Ok(Some(new_tls_data)) => {
      let mut tls_data = tls_data_lock()
        .await
        .write()
        .expect("error getting write-access to TlsData");
      *tls_data = new_tls_data;
    }
    Ok(None) => {
      if verbose {
        info!("Certificate is already up to date");
      }
    }
    Err(err) => error!("Error updating certificate: {}", err),
  }
}

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
    if name.starts_with("__MACOSX/")
      || (!name.ends_with(".pem") && !name.ends_with(".crt") && !name.ends_with(".key"))
    {
      continue;
    }

    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;
    let mut file_reader = BufReader::new(file_data.as_slice());

    if name.starts_with("privkey") || name.ends_with(".key") {
      key = Some(rustls_pemfile::private_key(&mut file_reader).map(|key| key.unwrap())?);
    } else if name.starts_with("fullchain") || name.ends_with(".crt") {
      certs =
        Some(rustls_pemfile::certs(&mut file_reader).collect::<io::Result<Vec<CertificateDer>>>()?);
    }
    if certs.is_some() && key.is_some() {
      break;
    }
  }

  if certs.is_none() || key.is_none() {
    return Err("certificate or key not found in zip file".into());
  }

  return Ok((certs.unwrap(), key.unwrap()));
}

pub async fn get_tls_data() -> Result<Option<TlsData>, Box<dyn Error + Send + Sync>> {
  let certs: Vec<CertificateDer<'_>>;
  let cert_key: PrivateKeyDer<'_>;

  if let Ok(certificate_url) = env::var("CERTIFICATE_URL") {
    info!("Downloading certificate bundle from {}", certificate_url);

    let etag_option = etag().read().unwrap().to_owned();
    let new_etag: Option<String>;
    let zip_cursor: Cursor<hyper::body::Bytes>;

    if certificate_url.starts_with("s3://") {
      let (bucket, key) = s3_url::parse(certificate_url.as_str())?;

      let region_provider =
        aws_config::meta::region::RegionProviderChain::default_provider().or_else("us-east-1");
      let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
      let mut s3_config = aws_sdk_s3::config::Builder::from(&shared_config);
      if let Ok(s3_endpoint) = std::env::var("AWS_S3_ENDPOINT") {
        s3_config = s3_config.endpoint_url(s3_endpoint).force_path_style(true);
      }
      let s3_client = aws_sdk_s3::client::Client::from_conf(s3_config.build());
      let object_result = s3_client
        .get_object()
        .bucket(bucket)
        .key(key)
        .set_if_none_match(etag_option)
        .send()
        .await;

      if let Err(err) = object_result {
        if let aws_sdk_s3::error::SdkError::ServiceError(ref svc_err) = err {
          let response = svc_err.raw();
          if response.status().as_u16() == 304 {
            return Ok(None);
          }
        }
        return Err(Box::new(err));
      }

      let object = object_result?;
      let object_body = object.body.collect().await.map(|data| data.into_bytes())?;
      zip_cursor = Cursor::new(object_body);
      new_etag = object.e_tag;
    } else {
      let client = reqwest::Client::new();
      let mut request = client.get(certificate_url);

      if let Some(etag_value) = etag_option {
        request = request.header("If-None-Match", etag_value);
      }

      let response = request.send().await?;
      if response.status() == StatusCode::NOT_MODIFIED {
        return Ok(None);
      } else if response.status() != StatusCode::OK {
        return Err(format!("Status code received: {}", response.status()).into());
      }
      let response_etag = response
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok().map(|v| v.to_string()));

      let response_body = response.bytes().await?;
      zip_cursor = Cursor::new(response_body);
      new_etag = response_etag;
    }

    let data = extract_cert_and_key(zip_cursor)?;
    certs = data.0;
    cert_key = data.1;

    if new_etag.is_some() {
      let mut etag_option = etag().write().unwrap();
      *etag_option = new_etag;
    }
  } else {
    let certificate_path = env::var("CERTIFICATE_PATH")?;
    let certificate_key_path = env::var("CERTIFICATE_KEY_PATH")?;

    let certfile = fs::File::open(certificate_path)?;
    let mut reader = BufReader::new(certfile);
    certs = rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<CertificateDer>>>()?;

    let keyfile = fs::File::open(certificate_key_path)?;
    let mut reader = BufReader::new(keyfile);
    cert_key = rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())?;
  }

  let cert = X509Certificate::from_der(certs.first().unwrap())?;
  let cert_names = cert
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
  info!(
    "Loading certificate for DNS names: {}",
    cert_names.join(", ")
  );

  let not_after = cert.1.validity.not_after.timestamp() as u64;
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
  info!(
    "Expires at: {} ({})",
    cert.1.validity.not_after,
    not_after
      .checked_sub(now)
      .map(|seconds| format!("in {}", utils::humanize_duration(seconds)))
      .unwrap_or("EXPIRED".to_string())
  );

  let mut server_config = if *require_sni() {
    let provider = aws_lc_rs::default_provider();
    let certified_key = sign::CertifiedKey::from_der(certs, cert_key, &provider)
      .expect("error parsing certificate and key");
    ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(Arc::new(CertResolver {
        certified_key: Arc::new(certified_key),
        cert_names,
      }))
  } else {
    ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(certs, cert_key)?
  };

  server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()];

  if env::var("USE_H2").is_ok() {
    // Warning: Make sure your upstream service supports HTTP/2
    server_config.alpn_protocols.insert(0, b"h2".to_vec());
  }

  return Ok(Some(TlsData {
    tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
    not_after,
  }));
}
