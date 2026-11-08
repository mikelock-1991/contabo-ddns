# Builder image. dependency-updates.yml moves this to the newest stable Rust -alpine tag and its manifest-list digest.
FROM rust:1.99.1-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS builder
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Build dependencies against a stub so source edits reuse this layer.
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# Runtime image. dependency-updates.yml moves this to the newest Alpine x.y.z and its manifest-list digest.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 1000 -h /home/app app \
    && mkdir -p /var/log/contabo-ddns \
    && chown app:app /var/log/contabo-ddns
COPY --from=builder /src/target/release/contabo-ddns /usr/local/bin/contabo-ddns
USER app
ENV LOG_DIR=/var/log/contabo-ddns
ENTRYPOINT ["contabo-ddns"]
