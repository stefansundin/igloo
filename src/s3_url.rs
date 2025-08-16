// https://github.com/awslabs/aws-sdk-rust/issues/522

use std::error::Error;
use std::fmt::{Display, Formatter};

pub fn parse(s: &str) -> Result<(String, String), ParseS3UrlError> {
  if !s.starts_with("s3://") {
    return Err(ParseS3UrlError::InvalidFormat);
  }
  let slash_index = s[5..].find('/').map(|i| i + 5);
  if slash_index.is_none() || slash_index == Some(6) {
    // Missing slash (s3://foo) or missing bucket name (s3:///key)
    return Err(ParseS3UrlError::InvalidFormat);
  }
  let slash_index = slash_index.unwrap();
  let bucket = s[5..slash_index].to_string();
  let key = s[slash_index + 1..].to_string();
  Ok((bucket, key))
}

#[derive(Debug, PartialEq)]
pub enum ParseS3UrlError {
  InvalidFormat,
}

impl Display for ParseS3UrlError {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      ParseS3UrlError::InvalidFormat => write!(f, "Error parsing S3 URL"),
    }
  }
}

impl Error for ParseS3UrlError {}
