# Builder image. dependency-updates.yml moves this to the newest stable Rust
# Docker Hardened Image (debian13 dev) and its manifest-list digest.
# That image ships rustc and cargo, not rustup. The musl standard library
# comes from the matching standalone component. Rust 1.99 links musl itself.
# ring still compiles C, and cc looks up <arch>-linux-musl-gcc for this target.
# BuildKit sets TARGETARCH to amd64 or arm64.
FROM dhi.io/rust:1.99.1-debian13-dev@sha256:caad43bd38067fba8be69a1540c3350d1ff3269e731065801b4b91bb17313301 AS builder
ARG TARGETARCH
# dependency-updates.yml moves these pins to the apt candidate in the builder.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         curl=8.14.1-2+deb13u7 \
         xz-utils=5.8.1-1+deb13u2 \
         musl-tools=1.2.5-3.1~deb13u1 \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/bin/musl-gcc \
    && test -x /usr/bin/ar \
    && case "$TARGETARCH" in \
         amd64) rust_target=x86_64-unknown-linux-musl; musl_triple=x86_64-linux-musl ;; \
         arm64) rust_target=aarch64-unknown-linux-musl; musl_triple=aarch64-linux-musl ;; \
         *) echo "unsupported architecture: ${TARGETARCH:-empty}"; exit 1 ;; \
       esac \
    && ln -sf /usr/bin/musl-gcc "/usr/local/bin/${musl_triple}-gcc" \
    && ln -sf /usr/bin/ar "/usr/local/bin/${musl_triple}-ar" \
    && printf '%s\n' "$rust_target" > /etc/rust-target \
    && rustc_line="$(rustc --version)" \
    && rust_version="${rustc_line#* }" \
    && rust_version="${rust_version%% *}" \
    && case "$rust_version" in \
         [0-9]*.[0-9]*.[0-9]*) ;; \
         *) echo "unexpected rustc version: ${rust_version:-empty}"; exit 1 ;; \
       esac \
    && curl -fsSL "https://static.rust-lang.org/dist/rust-std-${rust_version}-${rust_target}.tar.xz" -o /tmp/rust-std.tar.xz \
    && tar -xJf /tmp/rust-std.tar.xz -C /tmp \
    && "/tmp/rust-std-${rust_version}-${rust_target}/install.sh" --prefix=/usr/local --disable-ldconfig \
    && test -d "$(rustc --print sysroot)/lib/rustlib/${rust_target}/lib" \
    && rm -rf /tmp/rust-std.tar.xz "/tmp/rust-std-${rust_version}-${rust_target}"
# Static musl for the program only. Proc macros stay on the glibc host.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Build dependencies against a stub so source edits reuse this layer.
RUN rust_target="$(cat /etc/rust-target)" \
    && mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked --target "$rust_target" \
    && rm -rf src
COPY src ./src
RUN rust_target="$(cat /etc/rust-target)" \
    && touch src/main.rs \
    && cargo build --release --locked --target "$rust_target" \
    && bin="/src/target/${rust_target}/release/contabo-ddns" \
    && ldd_out="$(ldd "$bin" 2>&1 || true)" \
    && case "$ldd_out" in \
         *.so*) echo "$ldd_out"; echo "binary must be static for the hardened static image"; exit 1 ;; \
         *"statically linked"*|*"not a dynamic executable"*) ;; \
         *) echo "$ldd_out"; echo "binary must be static for the hardened static image"; exit 1 ;; \
       esac \
    && mkdir -p /out /var/log/contabo-ddns \
    && cp "$bin" /out/contabo-ddns

# Runtime image. dependency-updates.yml refreshes this tag and its manifest-list digest.
# Docker Hardened Image static, Debian 13. nonroot is uid 65532.
# The image has CA certificates and no shell.
FROM dhi.io/static:20250419-debian13@sha256:4749130e822c145dbdf9ca11ec0cc2f694b5fe687fd74268a2b62160e6726f39
COPY --from=builder /out/contabo-ddns /usr/local/bin/contabo-ddns
COPY --from=builder --chown=65532:65532 /var/log/contabo-ddns /var/log/contabo-ddns
USER 65532:65532
ENV LOG_DIR=/var/log/contabo-ddns
# Loopback only. The static image has no shell, so Docker calls the binary.
ENV HEALTHCHECK_BIND=127.0.0.1:8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/contabo-ddns", "health"]
ENTRYPOINT ["contabo-ddns"]
