#![allow(clippy::needless_return)]

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, io, process};

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HOST, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_reverse_proxy::ReverseProxy;
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use log::{debug, error, info, warn};
use rustls::{
  ClientConfig, KeyLogFile,
  crypto::{CryptoProvider, aws_lc_rs},
};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{interval, sleep};

pub mod cert;
pub mod cert_resolver;
pub mod s3_url;
pub mod utils;

type Connector = HttpsConnector<HttpConnector>;
type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

fn upstream_url() -> &'static str {
  static UPSTREAM_URL: OnceLock<String> = OnceLock::new();
  UPSTREAM_URL.get_or_init(|| env::var("UPSTREAM_URL").expect("UPSTREAM_URL is not configured"))
}

fn allowed_hosts() -> &'static Vec<&'static str> {
  static ALLOWED_HOSTS: OnceLock<Vec<&str>> = OnceLock::new();
  ALLOWED_HOSTS.get_or_init(|| {
    env::var("ALLOWED_HOSTS")
      .map(|v| v.leak().split(',').collect())
      .unwrap_or_default()
  })
}

fn http_redirect_to() -> &'static Option<String> {
  static HTTP_REDIRECT_TO: OnceLock<Option<String>> = OnceLock::new();
  HTTP_REDIRECT_TO.get_or_init(|| env::var("HTTP_REDIRECT_TO").ok())
}

fn strict_transport_security() -> &'static HeaderName {
  static STRICT_TRANSPORT_SECURITY: OnceLock<HeaderName> = OnceLock::new();
  STRICT_TRANSPORT_SECURITY.get_or_init(|| HeaderName::from_static("strict-transport-security"))
}

fn hsts() -> &'static Option<HeaderValue> {
  static HSTS: OnceLock<Option<HeaderValue>> = OnceLock::new();
  HSTS.get_or_init(|| {
    env::var("HSTS")
      .ok()
      .map(|value| HeaderValue::from_static(value.leak()))
  })
}

fn proxy_client() -> &'static ReverseProxy<Connector> {
  static PROXY_CLIENT: OnceLock<ReverseProxy<Connector>> = OnceLock::new();
  PROXY_CLIENT.get_or_init(|| {
    let mut tls_config = ClientConfig::builder()
      .with_native_roots()
      .expect("with_native_roots")
      .with_no_client_auth();
    tls_config.key_log = Arc::new(KeyLogFile::new());
    let connector = Connector::builder()
      .with_tls_config(tls_config)
      .https_or_http()
      .enable_http1()
      .enable_http2()
      .build();
    let mut client_builder = hyper_util::client::legacy::Builder::new(TokioExecutor::new());
    if let Ok(v) = env::var("IDLE_TIMEOUT") {
      let idle_timeout = v.parse::<u64>().expect("error parsing IDLE_TIMEOUT");
      client_builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(idle_timeout));
    }
    let client = client_builder.build::<_, Incoming>(connector);
    ReverseProxy::new(client)
  })
}

async fn handle(
  mut req: Request<Incoming>,
  client_ip: IpAddr,
  https: bool,
) -> Result<Response<ResponseBody>, Infallible> {
  debug!("{:?}", req);

  let allowed_hosts = allowed_hosts();
  if !allowed_hosts.is_empty() {
    let host = req.headers().get("host").and_then(|v| {
      v.to_str()
        .map(|v| {
          let port_sep = v.find(':');
          if let Some(idx) = port_sep {
            v.split_at(idx).0
          } else {
            v
          }
        })
        .ok()
    });
    if !utils::includes_host(&host, allowed_hosts) {
      return Ok(
        Response::builder()
          .status(StatusCode::NOT_FOUND)
          .body(UnsyncBoxBody::new(
            Empty::<Bytes>::new().map_err(io::Error::other),
          ))
          .unwrap(),
      );
    }
  }

  if let (false, Some(http_redirect_to)) = (https, http_redirect_to()) {
    if req.method() != Method::GET {
      return Ok(
        Response::builder()
          .status(StatusCode::METHOD_NOT_ALLOWED)
          .body(UnsyncBoxBody::new(
            Empty::<Bytes>::new().map_err(io::Error::other),
          ))
          .unwrap(),
      );
    }
    return Ok(
      Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Location", format!("{}{}", http_redirect_to, req.uri()))
        .body(UnsyncBoxBody::new(
          Empty::<Bytes>::new().map_err(io::Error::other),
        ))
        .unwrap(),
    );
  }

  if let Ok(rewrite_host) = env::var("REWRITE_HOST")
    && let Ok(val) = HeaderValue::from_str(&rewrite_host)
  {
    req.headers_mut().insert(HOST, val);
  }

  match proxy_client().call(client_ip, upstream_url(), req).await {
    Ok(mut response) => {
      if let Some(value) = hsts() {
        response
          .headers_mut()
          .insert(strict_transport_security(), value.clone());
      }
      debug!("{:?}", response);
      Ok(response)
    }
    Err(err) => {
      error!("Error proxying request: {:?}", err);
      Ok(
        Response::builder()
          .status(StatusCode::INTERNAL_SERVER_ERROR)
          .body(UnsyncBoxBody::new(
            Empty::<Bytes>::new().map_err(io::Error::other),
          ))
          .unwrap(),
      )
    }
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  env_logger::init_from_env(env_logger::Env::default().default_filter_or("igloo=info"));
  CryptoProvider::install_default(aws_lc_rs::default_provider())
    .expect("error installing CryptoProvider");

  // Send the process a SIGTERM to terminate the program
  tokio::spawn(async {
    let mut sigterm = signal(SignalKind::terminate()).expect("error listening for SIGTERM");
    sigterm.recv().await;
    debug!("Received SIGTERM");
    process::exit(0);
  });

  let host = env::var("HOST").unwrap_or("[::]".to_string());
  let http_port = env::var("HTTP_PORT")
    .unwrap_or("3000".to_string())
    .parse::<u16>()
    .expect("error parsing HTTP_PORT");
  let https_port = env::var("HTTPS_PORT")
    .unwrap_or("3001".to_string())
    .parse::<u16>()
    .expect("error parsing HTTPS_PORT");
  upstream_url(); // ensure UPSTREAM_URL is set
  proxy_client(); // ensure the proxy client can be built successfully

  let use_https = env::var("CERTIFICATE_URL").is_ok()
    || (env::var("CERTIFICATE_PATH").is_ok() && env::var("CERTIFICATE_KEY_PATH").is_ok());
  if use_https {
    let bind_addr = format!("{}:{}", host, https_port);
    let addr = bind_addr
      .parse::<SocketAddr>()
      .expect("error parsing bind address");

    let listener = TcpListener::bind(addr).await?;
    info!("Starting HTTPS reverse proxy on port {}", https_port);

    // Eagerly load the certificate
    cert::tls_data_lock().await;

    // Send the process a SIGHUP to reload the certificate
    tokio::spawn(async {
      let mut sighup = signal(SignalKind::hangup()).expect("error listening for SIGHUP");
      while sighup.recv().await.is_some() {
        cert::reload_cert(true).await;
      }
    });

    // Check for a new certificate when the expiration date nears
    tokio::spawn(async {
      if env::var("CERTIFICATE_URL").is_ok() {
        loop {
          let not_after = cert::tls_data_lock().await.read().unwrap().not_after;
          let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
          let seconds_until_expiration = not_after.saturating_sub(now);

          if seconds_until_expiration == 0 {
            warn!("WARNING: The certificate has expired!!");
          } else if seconds_until_expiration < 24 * 60 * 60 {
            warn!("WARNING: The certificate expires soon!!");
          }

          // Check progressively more often the closer the expiration date gets, starting 7 days before the expiration date
          let seconds_to_sleep = if seconds_until_expiration > 8 * 24 * 60 * 60 {
            24 * 60 * 60 + seconds_until_expiration - 8 * 24 * 60 * 60
          } else if seconds_until_expiration > 2 * 24 * 60 * 60 {
            24 * 60 * 60 + seconds_until_expiration % (24 * 60 * 60)
          } else if seconds_until_expiration > 24 * 60 * 60 {
            60 * 60 + seconds_until_expiration % (24 * 60 * 60)
          } else if seconds_until_expiration > 2 * 60 * 60 {
            60 * 60 + seconds_until_expiration % (60 * 60)
          } else if seconds_until_expiration > 60 * 60 {
            5 * 60 + seconds_until_expiration % (60 * 60)
          } else if seconds_until_expiration > 5 * 60 {
            60 + seconds_until_expiration % (5 * 60)
          } else {
            60
          };

          sleep(Duration::from_secs(seconds_to_sleep)).await;

          let not_after_post_sleep = cert::tls_data_lock().await.read().unwrap().not_after;
          if not_after != not_after_post_sleep {
            // Certificate was already reloaded manually with a SIGHUP
            continue;
          }

          cert::reload_cert(false).await;
        }
      } else if let Ok(certificate_path) = env::var("CERTIFICATE_PATH") {
        // Since filesystem access is cheap, check once every minute if the certificate file has been modified
        let mut mtime = utils::get_file_mtime(&certificate_path);
        let mut interval = interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
          interval.tick().await;
          let new_mtime = utils::get_file_mtime(&certificate_path);
          if new_mtime == mtime {
            continue;
          }
          mtime = new_mtime;
          if mtime.is_some() {
            cert::reload_cert(false).await;
          }
        }
      }
    });

    tokio::task::spawn(async move {
      loop {
        let (stream, remote_addr) = listener.accept().await.expect("error accepting connection");
        let client_ip = remote_addr.ip();
        let tls_accept = cert::tls_data_lock()
          .await
          .read()
          .unwrap()
          .tls_acceptor
          .accept(stream);

        tokio::task::spawn(async move {
          let tls_stream = match tls_accept.await {
            Ok(tls_stream) => tls_stream,
            Err(err) => {
              debug!("TLS handshake error: {:?}", err);
              return;
            }
          };
          let io = TokioIo::new(tls_stream);

          if let Err(err) = auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, service_fn(move |req| handle(req, client_ip, true)))
            .await
          {
            error!("Error serving connection: {:?}", err);
          }
        });
      }
    });
  }

  let bind_addr = format!("{}:{}", host, http_port);
  let addr = bind_addr
    .parse::<SocketAddr>()
    .expect("error parsing bind address");
  let listener = TcpListener::bind(addr).await?;
  info!("Starting HTTP reverse proxy on port {}", http_port);

  loop {
    let (stream, remote_addr) = listener.accept().await?;
    let client_ip = remote_addr.ip();
    let io = TokioIo::new(stream);

    tokio::task::spawn(async move {
      if let Err(err) = http1::Builder::new()
        .serve_connection(io, service_fn(move |req| handle(req, client_ip, false)))
        .await
      {
        error!("Error serving connection: {:?}", err);
      }
    });
  }
}
