# contabo-sync

Rust container that updates Contabo DNS A records and the IPv4 sources of named firewall rules. It runs under Docker or Podman.

Run it on the network whose public address should be published. On the Contabo VPS, ipecho returns the VPS address. At home, it returns the home address.

## Run

```sh
cp .env.example .env
podman compose up -d --build
```

`docker compose` uses the same [compose.yaml](compose.yaml). Logs are written to stdout and to `/var/log/contabo-sync`, mounted on the `contabo-sync-logs` volume. The file rolls at `LOG_ROTATE_SIZE_MB` and `LOG_ROTATE_KEEP` older files are deleted. A host bind mount must be writable by uid 1000.

One shot, then exit:

```sh
podman run --rm --env-file .env -e INTERVAL_SECONDS=0 -v contabo-sync-logs:/var/log/contabo-sync contabo-sync
```

Set `LOG_DIR` to an empty string to keep stdout only. `DRY_RUN=true` logs the writes and does not call PATCH or PUT.

## Environment

Auth comes from the Contabo customer panel: client id, client secret, API user, and API password.

`RUN_ON_START` defaults to true. `INTERVAL_SECONDS` defaults to 300 and must be `0` or at least 30. `0` runs once and exits. `RUN_ON_START=false` with `INTERVAL_SECONDS=0` is rejected. `LOG_ROTATE_KEEP` must be between 1 and 10000. Required credentials that are empty or only whitespace are rejected.

`DNS_RECORDS` is a comma-separated list of hostnames. `home.example.com` updates that name. `example.com` is the apex and is created as `@`. `*.example.com` updates every existing A record for `example.com` and its subdomains. Other record types are left alone. Missing A records are created only when `DNS_CREATE_MISSING=true`, and only for exact names. `DNS_TTL` must be at least 1 when set. `DNS_ENABLED=false` turns DNS off even when `DNS_RECORDS` is set. Each cycle lists records only for zones that can contain a configured name.

`IP_ECHO_URL` is one `https://` URL or a comma-separated list. Each URL is tried in order. Answers that are private, loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), or benchmarking (`198.18.0.0/15`) are skipped.

Transient HTTP failures are retried up to three times with a 1s, 2s, then 4s pause. GET, PATCH, PUT, and the token request retry on timeouts, connection errors, 429, and 5xx. A DNS record POST retries only on 429, because a 5xx or timeout may follow a create that already happened.

If the public IP lookup fails, DNS is skipped and the cycle reports an error. The firewall still syncs unless one of its rules uses `current`.

`SIGTERM` and `SIGINT` stop the process during the sleep between cycles and cut a retry pause short. Compose sets `init: true` so the container still reaps child processes, and `stop_grace_period: 45s` so a stop during a 30s HTTP request still exits cleanly. The container runs with a read-only root filesystem, no capabilities, and `no-new-privileges`. A firewall PUT replaces the whole inbound rule list from the last GET, so a console edit made during that window can be overwritten.

`FIREWALL_RULES` is a JSON array:

```json
[
  {
    "displayName": "SSH",
    "sources": ["203.0.113.5", "home.example.net", "current"]
  }
]
```

Set exactly one of `FIREWALL_ID` or `FIREWALL_NAME`. `FIREWALL_ENABLED=false` turns the firewall off even when `FIREWALL_RULES` is set. A source must be an IPv4 address, an IPv4 CIDR, a hostname (every A record becomes `/32`), or `current` (the ipecho address). A bad source is rejected at startup. The matching rule's IPv4 sources are replaced. IPv6 sources, other rules, and unknown fields are copied through. If a name is missing, a hostname does not resolve, or the new source list would be empty, the firewall is not updated. A name lookup is cached until a GET for that id returns 404.

`TLS_ROOTS` chooses the HTTPS trust store: `both` (default) uses the embedded Mozilla roots and the image `ca-certificates` bundle, `webpki` uses only the embedded roots, and `native` uses only the bundle.

`CONTABO_API_BASE`, `CONTABO_AUTH_URL`, and `IP_ECHO_URL` must be `https://` URLs.

## Tests

```sh
cargo test
cargo coverage
cargo check-fmt
cargo lint
```

DNS and firewall updates run on separate threads after the public IP is fetched. `cargo coverage` prints an LLVM summary and exits non-zero when the crate is below 100% lines, regions, and functions, or when any source file is below 100% line coverage. Tests use the default thread pool. It needs the `llvm-tools-preview` rustup component and `cargo-llvm-cov`:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
```

Coverage is exercised with env parsing tests, scripted Contabo HTTP fixtures, local Reqwest stubs on `127.0.0.1`, and startup tests that call `main` with a minimal environment. No test reaches the network.

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs `check-fmt`, `lint`, and `coverage` on Ubuntu, then builds the Docker image. The Dockerfile builds dependencies in a separate layer, so source-only edits rebuild quickly.
