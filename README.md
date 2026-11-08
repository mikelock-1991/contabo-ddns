# contabo-ddns

Container that updates Contabo DNS A records and the IPv4 sources of named firewall rules. Run it on the network whose public address should be published. On the Contabo VPS, the echo service returns the VPS address. At home, it returns the home address.

The published image is `gcr.io/distroless/static-debian13:nonroot`. The process user is uid 65532. There is no shell. The root filesystem is read-only, all capabilities are dropped, and `no-new-privileges` is set. The only writable path is the log directory.

## Configure

```sh
cp .env.example .env
```

Fill in the four Contabo credentials from the customer panel (API section): client id, client secret, API user, and API password. Blank or whitespace-only values are rejected.

At least one of DNS or the firewall must be enabled. Booleans accept `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`. Case does not matter.

`CONTABO_API_BASE`, `CONTABO_AUTH_URL`, and every `IP_ECHO_URL` must start with `https://`.

| Variable                  | Default                           | Purpose                                                                                                                      |
| ------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `CONTABO_CLIENT_ID`       | required                          | OAuth client id. Trimmed.                                                                                                    |
| `CONTABO_CLIENT_SECRET`   | required                          | OAuth client secret. Not trimmed.                                                                                            |
| `CONTABO_API_USER`        | required                          | API user email. Trimmed.                                                                                                     |
| `CONTABO_API_PASSWORD`    | required                          | API password. Not trimmed.                                                                                                   |
| `CONTABO_API_BASE`        | `https://api.contabo.com`         | API origin.                                                                                                                  |
| `CONTABO_AUTH_URL`        | Contabo token endpoint            | OAuth token URL.                                                                                                             |
| `RUN_ON_START`            | `true`                            | `false` waits `INTERVAL_SECONDS` before the first sync.                                                                      |
| `INTERVAL_SECONDS`        | `300`                             | Seconds between cycles. `0` runs once and exits. Any other value must be at least 30. `false` combined with `0` is rejected. |
| `DRY_RUN`                 | `false`                           | Log the DNS and firewall writes and skip POST, PATCH, and PUT.                                                               |
| `IP_ECHO_URL`             | `https://ipecho.net/plain`        | Comma-separated echo URLs, tried in order.                                                                                   |
| `IP_ECHO_TIMEOUT_SECONDS` | `10`                              | Seconds for each echo request. At least 1.                                                                                   |
| `DNS_ENABLED`             | on when `DNS_RECORDS` is set      | `false` turns DNS off even when records are set.                                                                             |
| `DNS_RECORDS`             | required while DNS is on          | Comma-separated hostnames.                                                                                                   |
| `DNS_TTL`                 | API default                       | When set, at least 1.                                                                                                        |
| `DNS_CREATE_MISSING`      | `false`                           | Create a missing A record for an exact name only.                                                                            |
| `FIREWALL_ENABLED`        | on when `FIREWALL_RULES` is set   | `false` turns the firewall off even when rules are set.                                                                      |
| `FIREWALL_ID`             | one of id or name                 | Firewall id.                                                                                                                 |
| `FIREWALL_NAME`           | one of id or name                 | Exact firewall name.                                                                                                         |
| `FIREWALL_RULES`          | required while the firewall is on | JSON array of `displayName` and `sources`.                                                                                   |
| `TLS_ROOTS`               | `both`                            | `both`, `webpki`, or `native`.                                                                                               |
| `LOG_LEVEL`               | `info`                            | `error`, `warn`, `info`, `debug`, or `trace`.                                                                                |
| `LOG_DIR`                 | `/var/log/contabo-ddns`           | Empty string logs to stdout only.                                                                                            |
| `LOG_FILE`                | `contabo-ddns.log`                | File name, not a path.                                                                                                       |
| `LOG_ROTATE_SIZE_MB`      | `10`                              | Megabytes before the file rolls. At least 1.                                                                                 |
| `LOG_ROTATE_KEEP`         | `5`                               | Rolled files to keep, from 1 to 10000.                                                                                       |
| `LOG_TO_STDOUT`           | `true`                            | `false` requires a non-empty `LOG_DIR`.                                                                                      |

`home.example.com` updates that A record. `example.com` is the zone apex and is written as `@`. `*.example.com` updates existing A records in that zone and its children. Wildcards do not create records. Other record types are left alone.

A firewall source is an IPv4 address, an IPv4 CIDR, a hostname, or `current`. A hostname contributes one `/32` per A record. `current` is the address returned by `IP_ECHO_URL`. Set exactly one of `FIREWALL_ID` or `FIREWALL_NAME`. Duplicate sources are dropped and the remaining order is kept.

`TLS_ROOTS=both` uses the embedded Mozilla roots and the image `ca-certificates` bundle. `webpki` uses only the embedded roots. `native` uses only the bundle.

Echo answers that are private, loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), or benchmarking (`198.18.0.0/15`) are skipped.

## Run

From this directory, with `.env` in place:

```sh
podman compose up -d --build
```

Docker uses the same [compose.yaml](compose.yaml):

```sh
docker compose up -d --build
```

Compose names the image `contabo-ddns`, restarts it unless it is stopped, and mounts the `contabo-ddns-logs` volume on `/var/log/contabo-ddns`. `stop_grace_period` is 45 seconds, which is longer than one 30 second HTTP timeout.

A published image is `ghcr.io/mikelock-1991/contabo-ddns` and `docker.io/mikelockengineering/contabo-ddns`. `latest` tracks `main`, `beta` tracks `dev`, and each release is also tagged with the `Cargo.toml` version. The deploy workflow logs in to Docker Hub with the `DOCKERHUB_USERNAME` variable and the `DOCKERHUB_TOKEN` secret (a Docker Hub access token with write access). Set both on the repository, or on the `main` and `dev` environments.

After the image starts and exits 2 with an empty environment, the workflow creates or updates GitHub Release `v<version>` on the commit that was built. A `dev` publish stays a prerelease. A `main` publish marks that same release as the latest. The notes are regenerated on every publish from the commits since the previous version tag. The automatic patch-bump commit is omitted. Log in first when the GitHub package is private:

```sh
podman login ghcr.io
podman run -d --name contabo-ddns --env-file .env \
  -v contabo-ddns-logs:/var/log/contabo-ddns \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  ghcr.io/mikelock-1991/contabo-ddns:latest
```

One sync, then exit:

```sh
podman run --rm --env-file .env -e INTERVAL_SECONDS=0 \
  -v contabo-ddns-logs:/var/log/contabo-ddns \
  contabo-ddns
```

Stdout only, with no log volume:

```sh
podman run --rm --env-file .env -e INTERVAL_SECONDS=0 -e LOG_DIR= \
  contabo-ddns
```

A host bind mount must be writable by uid 65532:

```sh
podman run --rm --env-file .env -e INTERVAL_SECONDS=0 \
  -v /var/log/contabo-ddns:/var/log/contabo-ddns:Z \
  contabo-ddns
```

Follow the container log:

```sh
podman compose logs -f
```

`SIGTERM` and `SIGINT` stop the process during the sleep between cycles and cut a retry pause short. Compose sets `init: true` so the container still reaps child processes. `podman compose down` removes the container and keeps the log volume. `podman compose down -v` deletes that volume too.

Exit code 2 means the environment or the log directory was rejected. Exit code 1 means a one-shot cycle failed. Exit code 0 means a one-shot cycle succeeded, or a looping process was stopped.

## What a cycle does

Each cycle fetches the public IP when DNS is on or a firewall rule uses `current`, then updates DNS and the firewall in parallel.

Transient HTTP failures are retried up to three extra times, waiting 1 second, then 2, then 4. GET, PATCH, PUT, and the token request retry on timeouts, connection errors, 429, and 5xx. A DNS record POST retries only on 429, because a 5xx or a timeout may follow a create that already happened.

If the public IP lookup fails, DNS is skipped and the cycle reports an error. The firewall still syncs unless one of its rules uses `current`.

The matching firewall rule's IPv4 sources are replaced. IPv6 sources, other rules, and unknown fields are copied through. If a rule name is missing, a hostname does not resolve, or the new source list would be empty, the firewall is not updated. A name lookup is cached until a GET for that id returns 404. A firewall PUT replaces the whole inbound rule list from the last GET, so a console edit made during that window can be overwritten.

## Tests

```sh
cargo test
cargo coverage
cargo check-fmt
cargo lint
```

`cargo coverage` needs the `llvm-tools-preview` component and `cargo-llvm-cov`:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
```

`cargo audit` checks `Cargo.lock` against the RustSec advisory database:

```sh
cargo install cargo-audit --locked
cargo audit
```
