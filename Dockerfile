FROM rust:1-bookworm AS builder

ARG TARGETARCH
ARG CARGO_BUILD_JOBS
ARG CARGO_BUILD_PROFILE=release-build

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=musl-gcc
ENV AR=ar
ENV RUST_BACKTRACE=full

RUN apt-get update && apt-get install -y musl-tools

RUN mkdir /dist
RUN cp /etc/ssl/certs/ca-certificates.crt /dist/

WORKDIR /src
ADD . .
RUN find

RUN rustup --version

RUN case "$TARGETARCH" in \
      arm64) TARGET=aarch64-unknown-linux-musl ;; \
      amd64) TARGET=x86_64-unknown-linux-musl ;; \
      *) echo "Does not support $TARGETARCH" && exit 1 ;; \
    esac && \
    rustup target add $TARGET && \
    cargo build --target $TARGET --profile $CARGO_BUILD_PROFILE && \
    mv target/$TARGET/$CARGO_BUILD_PROFILE/igloo /dist/


# Copy the binary into an empty docker image
FROM scratch

LABEL org.opencontainers.image.authors="Stefan Sundin"
LABEL org.opencontainers.image.url="https://github.com/stefansundin/igloo"

COPY --from=builder /dist /

ENV SSL_CERT_FILE=/ca-certificates.crt
ENV HOST=0.0.0.0
ENV HTTP_PORT=80
ENV HTTPS_PORT=443

EXPOSE 80 443

ENTRYPOINT [ "/igloo" ]
