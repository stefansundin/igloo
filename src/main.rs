use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;
use std::{env, io};

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_reverse_proxy::ReverseProxy;
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ClientConfig;
use tokio::net::TcpListener;

pub mod utils;

type Connector = HttpsConnector<HttpConnector>;
type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

fn upstream_url() -> &'static str {
  static UPSTREAM_URL: OnceLock<String> = OnceLock::new();
  UPSTREAM_URL.get_or_init(|| env::var("UPSTREAM_URL").expect("UPSTREAM_URL is not configured"))
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
    let connector: Connector = Connector::builder()
      .with_tls_config(
        ClientConfig::builder()
          .with_native_roots()
          .expect("with_native_roots")
          .with_no_client_auth(),
      )
      .https_or_http()
      .enable_http1()
      .build();
    let mut client = hyper_util::client::legacy::Builder::new(TokioExecutor::new());
    if let Ok(v) = env::var("IDLE_TIMEOUT") {
      let idle_timeout = v.parse::<u64>().expect("error parsing IDLE_TIMEOUT");
      client
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(idle_timeout));
    }
    ReverseProxy::new(client.build::<_, Incoming>(connector))
  })
}

async fn handle(
  req: Request<Incoming>,
  client_ip: IpAddr,
  https: bool,
) -> Result<Response<ResponseBody>, Infallible> {
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
    let host = req.headers().get("host").and_then(|v| v.to_str().ok());
    if host.is_none() {
      return Ok(
        Response::builder()
          .status(StatusCode::INTERNAL_SERVER_ERROR)
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

  match proxy_client().call(client_ip, &upstream_url(), req).await {
    Ok(mut response) => {
      if let Some(value) = hsts() {
        response
          .headers_mut()
          .insert(strict_transport_security(), value.clone());
      }
      Ok(response)
    }
    Err(err) => {
      eprintln!("Error proxying request: {:?}", err);
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
  let host = env::var("HOST").unwrap_or("0.0.0.0".to_string());
  let port = env::var("PORT")
    .unwrap_or("3000".to_string())
    .parse::<u16>()
    .expect("error parsing PORT");
  let https_port = env::var("HTTPS_PORT")
    .unwrap_or("3001".to_string())
    .parse::<u16>()
    .expect("error parsing HTTPS_PORT");
  upstream_url(); // ensure UPSTREAM_URL is set
  proxy_client(); // ensure the proxy client can be built successfully

  let use_https = env::var("CERTIFICATE_PATH").is_ok() && env::var("CERTIFICATE_KEY_PATH").is_ok();
  if use_https {
    let bind_addr = format!("{}:{}", host, https_port);
    let addr = bind_addr
      .parse::<SocketAddr>()
      .expect("error parsing bind address");

    let listener = TcpListener::bind(addr).await?;
    println!("Starting HTTPS reverse proxy on port {}", https_port);

    tokio::task::spawn(async move {
      loop {
        let tls_acceptor = utils::get_tls_acceptor().expect("error constructing the TLS acceptor");
        let (stream, remote_addr) = listener.accept().await.expect("error accepting connection");
        let client_ip = remote_addr.ip();

        tokio::task::spawn(async move {
          let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(err) => {
              eprintln!("TLS handshake error: {:?}", err);
              return;
            }
          };
          let io = TokioIo::new(tls_stream);
          if let Err(err) = auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, service_fn(move |req| handle(req, client_ip, true)))
            .await
          {
            eprintln!("Error serving connection: {:?}", err);
          }
        });
      }
    });
  }

  let bind_addr = format!("{}:{}", host, port);
  let addr = bind_addr
    .parse::<SocketAddr>()
    .expect("error parsing bind address");
  let listener = TcpListener::bind(addr).await?;
  println!("Starting HTTP reverse proxy on port {}", port);

  loop {
    let (stream, remote_addr) = listener.accept().await?;
    let client_ip = remote_addr.ip();
    let io = TokioIo::new(stream);

    tokio::task::spawn(async move {
      if let Err(err) = http1::Builder::new()
        .serve_connection(io, service_fn(move |req| handle(req, client_ip, false)))
        .await
      {
        eprintln!("Error serving connection: {:?}", err);
      }
    });
  }
}
