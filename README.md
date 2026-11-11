# contabo-ddns

Updates Contabo DNS A and AAAA records and the IPv4 and IPv6 sources of named firewall rules to this machine's public address. Run it on the network whose address should be published: a Contabo VPS publishes the VPS address; a machine at home publishes the home address. IPv6 stays off until `IPV6=true`.

The image contains a static Rust binary on a [Docker Hardened Image](https://docs.docker.com/dhi/). It runs as uid/gid **65532:65532** and has no shell. The Compose example below uses a read-only root filesystem, drops all capabilities, and enables `no-new-privileges`. Logs are the only persistent data.

Images are available on [Docker Hub](https://hub.docker.com/r/mikelockengineering/contabo-ddns) and GHCR:

- `docker.io/mikelockengineering/contabo-ddns`
- `ghcr.io/ml-engineering-nl/contabo-ddns`

`latest` tracks `main`; `beta` tracks `dev`. Releases also have version tags, with prereleases named `<version>-beta.N`. Published images support `linux/amd64` and `linux/arm64`, including Apple Silicon. Pulling a published image does not require access to `dhi.io`.

[Source code](https://github.com/ml-engineering-nl/contabo-ddns) | [Full environment example](https://github.com/ml-engineering-nl/contabo-ddns/blob/main/.env.example) | [MIT license](https://github.com/ml-engineering-nl/contabo-ddns/blob/main/LICENSE)

## Installation

The same Compose file and `.env` work with Docker and Podman. No source checkout is needed.

Create a `.env` file next to `compose.yaml`. Fill in the four credentials from the API credentials area of the Contabo customer panel, and replace `home.example.com` with a record in your Contabo DNS zone:

```dotenv
CONTABO_CLIENT_ID=
CONTABO_CLIENT_SECRET=
CONTABO_API_USER=
CONTABO_API_PASSWORD=

DNS_RECORDS=home.example.com
```

This minimal configuration updates DNS. Firewall updates and IPv6 can be enabled in the configuration below. The DNS zone must already exist in your Contabo account.

Save this as `compose.yaml`:

```yaml
services:
  contabo-ddns:
    image: docker.io/mikelockengineering/contabo-ddns:latest
    init: true
    env_file:
      - .env
    volumes:
      - contabo-ddns-logs:/var/log/contabo-ddns
    restart: unless-stopped
    stop_grace_period: 45s
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "/usr/local/bin/contabo-ddns", "health"]
      interval: 30s
      timeout: 5s
      start_period: 15s
      retries: 3

volumes:
  contabo-ddns-logs:
```

Start the service and follow its logs:

```sh
docker compose up -d
docker compose logs -f
```

With Podman, use `podman compose up -d` and `podman compose logs -f` instead. To pull from GHCR, change `image` to `ghcr.io/ml-engineering-nl/contabo-ddns:latest`; sign in to `ghcr.io` first if the package is private.

## Configuration

Edit `.env` to select the DNS records and firewall rules to update. At least one must be enabled. After changing `.env`, recreate the container so it receives the new environment:

```sh
docker compose up -d --force-recreate
```

### DNS records

`DNS_RECORDS` is a comma-separated list of record names:

```dotenv
DNS_RECORDS=home.example.com,example.com,*.example.net
```

- `home.example.com` updates that exact record.
- `example.com` is the zone apex, written as `@` in the API.
- `*.example.net` updates existing matching records in that zone and its children.

A records are updated when the public IPv4 address is known. AAAA records are also updated when `IPV6=true` and the public IPv6 address is known. Other record types are left alone. `DNS_CREATE_MISSING=true` creates a missing A or AAAA record for an exact name; wildcards never create records.

### Firewall rules

Add the firewall name and the rules whose sources should be replaced:

```dotenv
FIREWALL_NAME=web
FIREWALL_RULES=[{"displayName":"SSH","sources":["203.0.113.5","home.example.net","current"]}]
```

A source can be an IP address, a CIDR, a hostname, `current`, or `current6`. `current` uses the public IPv4 echo answer. `current6` uses the IPv6 answer and requires `IPV6=true`. A hostname contributes one `/32` per A record and one `/128` per AAAA record. Duplicates are removed while preserving order.

Set exactly one of `FIREWALL_NAME` or `FIREWALL_ID`. Names must match the firewall and rule display names exactly. IPv4 sources replace only the rule's IPv4 list; IPv6 sources replace only its IPv6 list. The other address family, other rules, and unknown fields are preserved. An unresolved hostname, missing rule, or empty source list prevents the firewall update.

For firewall-only operation, set `DNS_ENABLED=false`. DNS-only operation is the default when `DNS_RECORDS` is set and `FIREWALL_RULES` is absent.

### IPv6

Set `IPV6=true` to fetch the public IPv6 address and update AAAA records alongside A records. Include `current6` in a firewall rule's sources to publish that address there too. With IPv6 disabled, AAAA records are left unchanged and `current6` is rejected.

### DNS resolution

`DNS_RECORDS` selects records to update. `DNS_SERVERS` selects the nameservers used for outbound hostname lookups, including HTTP requests and firewall source hostnames.

- **`DNS_SERVERS` is unset, empty, or whitespace-only:** try system DNS first, with a two-second lookup deadline. If configuration cannot be loaded or a lookup fails or times out, use `1.1.1.1` and `8.8.8.8`. A warning identifies the failure and defaults, and explains how to override them.
- **`DNS_SERVERS` is non-empty:** use only those servers and skip system DNS configuration entirely. For example, `DNS_SERVERS=192.168.80.1,192.168.80.2`. An info log identifies the selected servers. Invalid values fail startup; lookup failures are reported without switching to system DNS or public defaults.

The server list accepts comma-separated IPv4/IPv6 addresses on port 53. Explicit servers and the default fallback do not read `/etc/resolv.conf` or use its search domains. `/etc/hosts` applies in both modes. Valid negative DNS answers, such as NXDOMAIN or no records, do not trigger fallback.

On Docker networks affected by replies from a different source port at `127.0.0.11`, explicit servers or the default fallback query upstream nameservers directly. No resolver-file mount or extra capabilities are needed. Public DNS cannot resolve Docker service names or private records, so choose reachable internal servers when those names are required. Allow outbound UDP/TCP port 53 to the selected servers.

## Environment variables

Required values cannot be blank or whitespace-only. Booleans accept `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`, without regard to case. At least one of DNS or the firewall must be enabled. `CONTABO_API_BASE`, `CONTABO_AUTH_URL`, and every `IP_ECHO_URL` must start with `https://`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONTABO_CLIENT_ID` | required | OAuth client id. Trimmed. |
| `CONTABO_CLIENT_SECRET` | required | OAuth client secret. Not trimmed. |
| `CONTABO_API_USER` | required | API user email. Trimmed. |
| `CONTABO_API_PASSWORD` | required | API password. Not trimmed. |
| `CONTABO_API_BASE` | `https://api.contabo.com` | API origin. |
| `CONTABO_AUTH_URL` | `https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token` | OAuth token URL. |
| `RUN_ON_START` | `true` | `false` waits `INTERVAL_SECONDS` before the first sync. |
| `INTERVAL_SECONDS` | `300` | Seconds between cycles. `0` runs once and exits. Any other value must be at least 30. `RUN_ON_START=false` combined with `0` is rejected. |
| `DRY_RUN` | `false` | Log the DNS and firewall writes and skip POST, PATCH, and PUT. |
| `IP_ECHO_URL` | `https://ipecho.net/plain` | Comma-separated echo URLs, tried in order. IPv4 is requested like `curl -4`. |
| `IPV6` | `false` | `true` also requests those URLs over IPv6 only, like `curl -6`. |
| `IP_ECHO_TIMEOUT_SECONDS` | `10` | Seconds for each echo request. At least 1. |
| `DNS_SERVERS` | unset | Non-empty: use these nameserver IPs directly, bypassing system DNS. Unset or blank: system DNS first, then public defaults on failure. |
| `DNS_ENABLED` | on when `DNS_RECORDS` is set | `true` requires `DNS_RECORDS`; `false` disables DNS updates. |
| `DNS_RECORDS` | required while DNS is on | Comma-separated hostnames. |
| `DNS_TTL` | API default | When set, at least 1. |
| `DNS_CREATE_MISSING` | `false` | Create a missing A or AAAA record for an exact name only. |
| `FIREWALL_ENABLED` | on when `FIREWALL_RULES` is set | `true` requires `FIREWALL_RULES`; `false` disables firewall updates. |
| `FIREWALL_ID` | one of id or name | Firewall id. |
| `FIREWALL_NAME` | one of id or name | Exact firewall name. |
| `FIREWALL_RULES` | required while the firewall is on | JSON array of `displayName` and `sources`. |
| `TLS_ROOTS` | `both` | `both`, `webpki`, or `native`. |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, or `trace`. |
| `LOG_DIR` | `/var/log/contabo-ddns` | Empty string logs to stdout only. |
| `LOG_FILE` | `contabo-ddns.log` | File name, not a path. |
| `LOG_ROTATE_SIZE_MB` | `10` | Megabytes before the file rolls. At least 1. |
| `LOG_ROTATE_KEEP` | `5` | Rolled files to keep, from 1 to 10000. |
| `LOG_TO_STDOUT` | `true` | `false` requires a non-empty `LOG_DIR`. |
| `HEALTHCHECK_BIND` | `127.0.0.1:8080` | Loopback address for `GET /health`. A non-loopback address is rejected. Do not publish the port. |

## Running without Compose

Use the `.env` file from the installation section:

```sh
docker run -d --name contabo-ddns --init --env-file .env \
  -v contabo-ddns-logs:/var/log/contabo-ddns \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --restart unless-stopped --stop-timeout 45 \
  docker.io/mikelockengineering/contabo-ddns:latest
```

Replace `docker` with `podman` for the same commands on Podman.

One sync, then exit:

```sh
docker run --rm --init --env-file .env -e INTERVAL_SECONDS=0 \
  -v contabo-ddns-logs:/var/log/contabo-ddns \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  docker.io/mikelockengineering/contabo-ddns:latest
```

One sync with stdout logging and no volume:

```sh
docker run --rm --init --env-file .env -e INTERVAL_SECONDS=0 -e LOG_DIR= \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  docker.io/mikelockengineering/contabo-ddns:latest
```

## Operations

### Healthcheck

The image healthcheck runs `contabo-ddns health` every 30 seconds. It requests `GET /health` at `127.0.0.1:8080` and expects `ok`. After the 15-second start period, `docker compose ps` reports the health status. Check logs for sync failures; the endpoint reports process availability.

Keep this port private. `HEALTHCHECK_BIND` accepts only loopback addresses. The image has no shell or curl, so the healthcheck calls the program directly.

### Logs and storage

Logs go to stdout and `/var/log/contabo-ddns` by default. Set `LOG_DIR=` to use stdout only. File logs rotate according to `LOG_ROTATE_SIZE_MB` and `LOG_ROTATE_KEEP`.

The recommended named volume is initialized from the image directory, which is owned by uid/gid 65532. A host bind mount must be prepared separately:

```sh
sudo install -d -o 65532 -g 65532 -m 750 /var/log/contabo-ddns
```

To retain root ownership, grant write access with an ACL (`setfacl` comes from the `acl` package):

```sh
sudo install -d -m 755 /var/log/contabo-ddns
sudo setfacl -m u:65532:rwx /var/log/contabo-ddns
```

Rootless Podman applies container uids inside its user namespace:

```sh
mkdir -p /var/log/contabo-ddns
podman unshare chown 65532:65532 /var/log/contabo-ddns
podman unshare chmod 750 /var/log/contabo-ddns
```

Or retain ownership and grant an ACL inside that namespace:

```sh
podman unshare setfacl -m u:65532:rwx /var/log/contabo-ddns
```

On a host with SELinux, use `:Z` on the bind mount so the directory can be relabeled:

```sh
podman run --rm --init --env-file .env -e INTERVAL_SECONDS=0 \
  -v /var/log/contabo-ddns:/var/log/contabo-ddns:Z \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  docker.io/mikelockengineering/contabo-ddns:latest
```

### Updates and shutdown

Pull the selected tag and recreate the service:

```sh
docker compose pull
docker compose up -d
```

`docker compose down` removes the container and keeps the log volume. Adding `-v` also deletes that volume. The same commands work with `podman compose`.

`SIGTERM` and `SIGINT` interrupt sleep and retry waits. An in-flight HTTP request can take up to 30 seconds; the Compose example allows 45 seconds to stop. `init: true` provides child-process reaping.

| Exit code | Meaning |
| --- | --- |
| `0` | One-shot cycle succeeded, or the looping process was stopped. |
| `1` | One-shot cycle failed, or startup could not create the healthcheck listener or HTTP/DNS client. |
| `2` | Environment validation or log setup failed. |

## What a cycle does

Each cycle fetches the public IPv4 address, over IPv4 only, when DNS is on or a firewall rule uses `current`. With `IPV6=true` it fetches the same echo URLs over IPv6 only when DNS is on or a rule uses `current6`. DNS and the firewall then update in parallel.

Transient HTTP failures are retried up to three extra times, waiting 1 second, then 2, then 4. GET, PATCH, PUT, and the token request retry on timeouts, connection errors, 429, and 5xx. A DNS record POST retries only on 429, because a 5xx or a timeout may follow a create that already happened.

If the IPv4 lookup fails, A records are left unchanged and the cycle reports an error. AAAA records still update when the IPv6 lookup succeeded. The firewall still syncs unless one of its rules uses `current` and the IPv4 address is unknown, or `current6` and the IPv6 address is unknown.

The matching firewall rule's configured address family is replaced. A rule with only IPv4 sources leaves `srcCidr.ipv6` unchanged, and a rule with only IPv6 sources leaves `srcCidr.ipv4` unchanged. Other rules and unknown fields are copied through. If a rule name is missing, a hostname does not resolve, or the new source list would be empty, the firewall is not updated. A name lookup is cached until a GET for that id returns 404. A firewall PUT replaces the whole inbound rule list from the last GET, so a console edit made during that window can be overwritten.

## Image and security

The runtime uses `dhi.io/static`, Debian 13, with a CA certificate bundle and a nonroot user. The program is a statically linked musl binary. There is no shell, package manager, or init process in the image. Use container logs or the mounted log files for diagnostics.

The recommended Compose file makes the root filesystem read-only, drops all capabilities, and enables `no-new-privileges`. The log volume provides writable storage for application logs. No incoming ports need to be published.

`TLS_ROOTS=both` combines the embedded Mozilla roots with the image CA bundle. `webpki` uses only the embedded roots; `native` uses only the bundle.

IPv4 echo answers that are private, loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), or benchmarking (`198.18.0.0/15`) are skipped. IPv6 answers that are loopback, link-local, unique-local, documentation (`2001:db8::/32`), benchmarking (`2001:2::/48`), discard-only (`100::/64`), or IPv4-mapped are skipped.

### Verify image signatures

The release workflow signs images with Sigstore using its GitHub Actions identity. No signing key is stored. Verify a published tag with cosign:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ml-engineering-nl/contabo-ddns/\.github/workflows/deploy\.yml@' \
  docker.io/mikelockengineering/contabo-ddns:latest
```

For a GHCR image, use the same command with `ghcr.io/ml-engineering-nl/contabo-ddns:latest`.

## Build from source

The repository's [compose.yaml](https://github.com/ml-engineering-nl/contabo-ddns/blob/main/compose.yaml) builds the local image. Clone the source and create the environment file:

```sh
git clone https://github.com/ml-engineering-nl/contabo-ddns.git
cd contabo-ddns
cp .env.example .env
```

Fill in `.env` as described above. Building pulls the builder and runtime images from `dhi.io`, so sign in with an account that has access to those base images:

```sh
docker login dhi.io
docker compose up -d --build
```

With Podman, use `podman login dhi.io` and `podman compose up -d --build`. A local build targets the host's architecture.

## Development and publishing

### Tests

```sh
cargo test
cargo coverage
cargo check-fmt
cargo lint
```

The Docker CI job loads the production image and runs it on user-defined bridge and macvlan networks on both amd64 and arm64. Each network is tested with UDP DNS and truncated UDP replies requiring TCP. It verifies working system DNS with unset or blank `DNS_SERVERS`, explicit nameservers with unreadable or unreachable system DNS, startup logs, and rejection of malformed `DNS_SERVERS`. Local DNS and HTTPS fixtures verify A/AAAA resolution, `/etc/hosts`, and the resulting DNS and firewall updates. The image smoke test uses dummy credentials and local DNS servers; it never contacts Contabo or public DNS.

To run the image smoke test on a rootful Linux Docker host:

```sh
docker buildx build --load --tag contabo-ddns:ci .
bash tests/docker/network-smoke.sh contabo-ddns:ci
```

The macvlan test creates and removes a dummy parent interface using `sudo ip`. A particular LAN's routing and firewall configuration still need testing on that LAN. Rust tests cover system DNS success and failure, explicit-server precedence, default fallback, and lookup deadlines.

`cargo coverage` requires `llvm-tools-preview` and `cargo-llvm-cov`:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
```

Check the dependency lockfile against the RustSec advisory database:

```sh
cargo install cargo-audit --locked
cargo audit
```

### Release workflow

Pushes to `main` and `dev` publish multi-architecture images to Docker Hub and GHCR. Each `dev` publish gets a numbered `<version>-beta.N` prerelease and moves the `beta` tag. Main releases move `latest`. The workflow creates or updates GitHub Release `v<version>` on the built commit and regenerates release notes; the automatic patch-bump commit is omitted from the notes.

Set `DOCKERHUB_USERNAME` as a variable and `DOCKERHUB_TOKEN` as a secret with write access on the repository or its `main` and `dev` environments. The workflow also uses those credentials to pull base images from `dhi.io`; `GITHUB_TOKEN` handles GHCR access. Each registry copy is signed with the deploy workflow's GitHub Actions identity.

This README is intended for both GitHub and the Docker Hub overview. The current deploy workflow publishes images but does not update the Docker Hub overview, so copy this same Markdown there when documentation changes.

---

[MIT license](https://github.com/ml-engineering-nl/contabo-ddns/blob/main/LICENSE) | [Powered by ML Engineering](https://ml-engineering.nl)
