Igloo is a small HTTP reverse proxy intended to solve the following problems:

- Terminate TLS and proxy requests to another host.
- Download the certificate and key from a private S3 bucket (never writing it to disk).
- Automatically checks for a new certificate when the current one nears expiration.
- Able to run as a Docker container.
- Written in Rust, small binary and minimal resource usage, making it suitable as a sidecar container.

Igloo is not yet able to automatically request or renew a certificate (from e.g. Let's Encrypt), but this capability may come in a future version. The normal operation is to manually renew the certificate and upload it to the S3 bucket, replacing the old certificate. Igloo will automatically download the new certificate before the old one expires.

See the [examples](examples) directory to get started.


## Docker image

The docker image is available on [Docker Hub](https://hub.docker.com/r/stefansundin/igloo) and [Amazon ECR](https://gallery.ecr.aws/stefansundin/igloo).

```
stefansundin/igloo:v0
```

```
public.ecr.aws/stefansundin/igloo:v0
```


## Configuration

You can configure igloo by setting these environment variables:

| Key                      | Description | Default in docker | Default in binary | Required? |
| ------------------------ | ----------- | ----------------- | ----------------- | --------- |
| `UPSTREAM_URL`           | Where to proxy requests to, e.g. `http://localhost:3000`. | Not set | Not set | **Required** |
| `CERTIFICATE_URL`        | Where to fetch the certificate from. Can be an `http://`, `https://`, or `s3://` URL. Should point to a `.zip` file with a `privkey*.pem` and `fullchain*.pem` or `*.key` and `*.crt`. Make sure your S3 bucket is private! | Not set | Not set | Optional |
| `CERTIFICATE_PATH`       | Path to a certificate file. | Not set | Not set | Optional |
| `CERTIFICATE_KEY_PATH`   | Path to the private key for the certificate. | Not set | Not set | Optional |
| `HOST`                   | The interface to listen to. Set to `127.0.0.1` to restrict connections to programs running on your computer. | `0.0.0.0` | `0.0.0.0` | Can use default |
| `HTTP_PORT`              | The port that igloo listens to for its HTTP server. | `80` | `3000` | Can use default |
| `HTTPS_PORT`             | The port that igloo listens to for its HTTPS server. | `443` | `3001` | Can use default |
| `HTTP_REDIRECT_TO`       | Set this to a URL to redirect HTTP traffic with a 301 redirect. You'd normally use this to redirect to the `https://` endpoint. Can optionally include a path, but you probably want to use something like `https://example.com` (i.e. without a trailing `/`). The request path is appended. | Not set | Not set | Optional |
| `ALLOWED_HOSTS`          | Comma-separated list of allowed `Host` headers in incoming requests. Useful if you want to ignore bot traffic. | Not set | Not set | Optional |
| `REWRITE_HOST`           | Rewrite the `Host` header when proxying requests to the upstream server. | Not set | Not set | Optional |
| `HSTS`                   | Set this to send a `Strict-Transport-Security` header in responses, e.g. `max-age=31536000`. | Not set | Not set | Optional |
| `IDLE_TIMEOUT`           | Configure the `Keep-Alive` idle timeout for HTTP/1.1. You may have to set this to a lower value than what your upstream server uses. The hyper default is 90 seconds. | Not set | Not set | Optional |
| `USE_H2`                 | Set this to enable HTTP/2. Requires that the upstream server also supports HTTP/2 (igloo is not able to translate requests to HTTP/1.1 yet). | Not set | Not set | Optional |
| `AWS_S3_ENDPOINT`        | Set this if you want to use a custom S3 endpoint. Setting this also forces path style access. | Not set | Not set | Optional |
| `RUST_LOG`               | Set this to adjust the log level. Use `igloo=debug` to see request-level logs. | `igloo=info` | `igloo=info` | Optional |
| `RUST_BACKTRACE`         | Set this to get a stack trace on crashes. Could be useful if you submit a bug report. | Not set | Not set | Optional |
| `SSLKEYLOGFILE`          | Debugging option that allows other programs to decrypt the TLS traffic. | Not set | Not set | Optional |
| `SSL_CERT_FILE`          | The CA bundle to use. | `/ca-certificates.crt` | Not set | Optional |

You can also set standard AWS environment variables like `AWS_PROFILE`, `AWS_DEFAULT_REGION`, etc.

## SIGHUP

You can force a certificate update check by sending igloo a SIGHUP signal:

```shell
docker ps
docker kill --signal=HUP container_id

# if you are using docker compose:
docker compose kill --signal=HUP igloo
```


## Development

```shell
export RUST_LOG=igloo=debug
cargo run
```
