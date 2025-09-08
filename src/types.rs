use rustls::sign::CertifiedKey;
use std::{error::Error, sync::Arc};

use crate::s3_url::ParseS3UrlError;

pub struct CertificateData {
  pub certified_key: Arc<CertifiedKey>,
  pub names: Vec<String>,
}

pub struct CertificateMetadata {
  pub etag: Option<String>,
  pub not_after: u64,
}

#[derive(Debug)]
pub enum GetCertificateDataError {
  NotModified,
  UnhandledError(Box<dyn Error + Send + Sync>),
}

impl From<Box<dyn Error + Send + Sync>> for GetCertificateDataError {
  fn from(err: Box<dyn Error + Send + Sync>) -> Self {
    Self::UnhandledError(err)
  }
}

impl From<rustls::Error> for GetCertificateDataError {
  fn from(err: rustls::Error) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<reqwest::Error> for GetCertificateDataError {
  fn from(err: reqwest::Error) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<std::io::Error> for GetCertificateDataError {
  fn from(err: std::io::Error) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<std::env::VarError> for GetCertificateDataError {
  fn from(err: std::env::VarError) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<ParseS3UrlError> for GetCertificateDataError {
  fn from(err: ParseS3UrlError) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<x509_parser::error::X509Error> for GetCertificateDataError {
  fn from(err: x509_parser::error::X509Error) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}

impl From<x509_parser::asn1_rs::Err<x509_parser::error::X509Error>> for GetCertificateDataError {
  fn from(err: x509_parser::asn1_rs::Err<x509_parser::error::X509Error>) -> Self {
    Self::UnhandledError(Box::new(err))
  }
}
