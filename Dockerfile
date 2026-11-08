FROM rust:1.99-alpine AS builder
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

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 1000 -h /home/app app \
    && mkdir -p /var/log/contabo-ddns \
    && chown app:app /var/log/contabo-ddns
COPY --from=builder /src/target/release/contabo-ddns /usr/local/bin/contabo-ddns
USER app
ENV LOG_DIR=/var/log/contabo-ddns
ENTRYPOINT ["contabo-ddns"]
