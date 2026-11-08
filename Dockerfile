# Builder image. dependency-updates.yml moves this to the newest stable Rust bookworm tag and its manifest-list digest.
FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
# Static musl for the program only. Proc macros stay on the glibc host.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Build dependencies against a stub so source edits reuse this layer.
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
    && rm -rf src
COPY src ./src
RUN touch src/main.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
    && ldd_out="$(ldd /src/target/x86_64-unknown-linux-musl/release/contabo-ddns)" \
    && case "$ldd_out" in *"statically linked"*) ;; *) echo "$ldd_out"; echo "binary must be static for distroless"; exit 1 ;; esac \
    && mkdir -p /var/log/contabo-ddns

# Runtime image. dependency-updates.yml refreshes this digest.
# nonroot is uid 65532. The image has CA certificates and no shell.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/contabo-ddns /usr/local/bin/contabo-ddns
COPY --from=builder --chown=65532:65532 /var/log/contabo-ddns /var/log/contabo-ddns
USER 65532:65532
ENV LOG_DIR=/var/log/contabo-ddns
ENTRYPOINT ["contabo-ddns"]
