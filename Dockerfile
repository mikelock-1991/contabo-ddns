# Builder image. dependency-updates.yml moves this to the newest stable Rust
# Docker Hardened Image (debian13 dev) and its manifest-list digest.
# That image ships rustc and cargo, not rustup. The musl standard library
# comes from the matching standalone component. Rust 1.99 links musl itself.
FROM dhi.io/rust:1.99.1-debian13-dev@sha256:caad43bd38067fba8be69a1540c3350d1ff3269e731065801b4b91bb17313301 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://static.rust-lang.org/dist/rust-std-${RUST_VERSION}-x86_64-unknown-linux-musl.tar.xz" -o /tmp/rust-std.tar.xz \
    && tar -xJf /tmp/rust-std.tar.xz -C /tmp \
    && "/tmp/rust-std-${RUST_VERSION}-x86_64-unknown-linux-musl/install.sh" --prefix=/usr/local --disable-ldconfig \
    && test -d "$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/lib" \
    && rm -rf /tmp/rust-std.tar.xz "/tmp/rust-std-${RUST_VERSION}-x86_64-unknown-linux-musl"
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
    && bin=/src/target/x86_64-unknown-linux-musl/release/contabo-ddns \
    && ldd_out="$(ldd "$bin" 2>&1 || true)" \
    && case "$ldd_out" in \
         *.so*) echo "$ldd_out"; echo "binary must be static for the hardened static image"; exit 1 ;; \
         *"statically linked"*|*"not a dynamic executable"*) ;; \
         *) echo "$ldd_out"; echo "binary must be static for the hardened static image"; exit 1 ;; \
       esac \
    && mkdir -p /var/log/contabo-ddns

# Runtime image. dependency-updates.yml refreshes this tag and its manifest-list digest.
# Docker Hardened Image static, Debian 13. nonroot is uid 65532.
# The image has CA certificates and no shell.
FROM dhi.io/static:20250419-debian13@sha256:4749130e822c145dbdf9ca11ec0cc2f694b5fe687fd74268a2b62160e6726f39
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/contabo-ddns /usr/local/bin/contabo-ddns
COPY --from=builder --chown=65532:65532 /var/log/contabo-ddns /var/log/contabo-ddns
USER 65532:65532
ENV LOG_DIR=/var/log/contabo-ddns
ENTRYPOINT ["contabo-ddns"]
