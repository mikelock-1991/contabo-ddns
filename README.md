# contabo-ddns

Rust program that updates Contabo DNS A and AAAA records and the IPv4 and IPv6 sources of named firewall rules. The published container is a static binary on a [Docker Hardened Image](https://docs.docker.com/dhi/). Run it on the network whose public address should be published. On the Contabo VPS, the echo service returns the VPS address. At home, it returns the home address. IPv6 stays off until `IPV6=true`.

## Run the published image

Pull a published tag. That pull does not use `dhi.io`. `latest` tracks `main` and is a multi-architecture image for `linux/amd64` and `linux/arm64`, including Apple Silicon. The same tags are on GHCR and Docker Hub:

- `ghcr.io/mikelock-1991/contabo-ddns`
- `docker.io/mikelockengineering/contabo-ddns`

```sh
cp .env.example .env
```

Fill in the four Contabo credentials. Save this next to `.env` as `compose.yaml`. If this repository is already checked out, remove `build` from the existing file and set `image` as shown.

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

```sh
docker compose up -d
```

Podman uses the same file: `podman compose up -d`. Log in to `ghcr.io` first when that package is private, then set `image` to `ghcr.io/mikelock-1991/contabo-ddns:latest`.

DNS lookups use Hickory inside the binary, bypassing musl's resolver. The program follows the system DNS configuration and `/etc/hosts`, including Docker's `127.0.0.11` on user-defined networks such as macvlan. It uses UDP with TCP fallback. For queries to `127.0.0.11:53` only, replies from another port on that same IP are accepted; query IDs, questions, and DNS records are still checked. Other DNS servers retain strict source address and port checks. No Compose DNS override or mounted `resolv.conf` is needed.

That Compose healthcheck runs `contabo-ddns health` every 30 seconds. Inside the container that is `GET /health` on `127.0.0.1:8080`, and the body `ok` means healthy. Do not publish the port. `HEALTHCHECK_BIND` can select another loopback address. Any other address is rejected. After the 15 second start period, `docker compose ps` shows `healthy`.

Follow the log with `docker compose logs -f`.

A named volume such as `contabo-ddns-logs` is created from the image directory, which is already owned by uid 65532. A host directory is not. Create it and give that user write access before using it as the log mount:

```sh
sudo install -d -o 65532 -g 65532 -m 750 /var/log/contabo-ddns
```

Rootless Podman maps container uids onto the host, so the same numbers have to be applied inside that mapping:

```sh
mkdir -p /var/log/contabo-ddns
podman unshare chown 65532:65532 /var/log/contabo-ddns
podman unshare chmod 750 /var/log/contabo-ddns
```

To leave the directory owned by root, add an ACL instead. `setfacl` comes from the `acl` package.

```sh
sudo install -d -m 755 /var/log/contabo-ddns
sudo setfacl -m u:65532:rwx /var/log/contabo-ddns
```

Rootless Podman again applies the container uid, not the host uid:

```sh
mkdir -p /var/log/contabo-ddns
podman unshare setfacl -m u:65532:rwx /var/log/contabo-ddns
```

## Configure

```sh
cp .env.example .env
```

Fill in the four Contabo credentials from the customer panel (API section): client id, client secret, API user, and API password. Blank or whitespace-only values are rejected.

At least one of DNS or the firewall must be enabled. Booleans accept `true`/`false`, `yes`/`no`, `on`/`off`, or `1`/`0`. Case does not matter.

`CONTABO_API_BASE`, `CONTABO_AUTH_URL`, and every echo URL must start with `https://`.

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
| `IP_ECHO_URL`             | `https://ipecho.net/plain`        | Comma-separated echo URLs, tried in order. IPv4 is requested like `curl -4`.                                                 |
| `IPV6`                    | `false`                           | `true` also requests those URLs over IPv6 only, like `curl -6`.                                                              |
| `IP_ECHO_TIMEOUT_SECONDS` | `10`                              | Seconds for each echo request. At least 1.                                                                                   |
| `DNS_ENABLED`             | on when `DNS_RECORDS` is set      | `false` turns DNS off even when records are set.                                                                             |
| `DNS_RECORDS`             | required while DNS is on          | Comma-separated hostnames.                                                                                                   |
| `DNS_TTL`                 | API default                       | When set, at least 1.                                                                                                        |
| `DNS_CREATE_MISSING`      | `false`                           | Create a missing A or AAAA record for an exact name only.                                                                    |
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
| `HEALTHCHECK_BIND`        | `127.0.0.1:8080`                  | Loopback address for `GET /health`. A non-loopback address is rejected. Do not publish the port.                             |

`home.example.com` updates that A record when a public IPv4 address is known, and that AAAA record when a public IPv6 address is known. `example.com` is the zone apex and is written as `@`. `*.example.com` updates existing A and AAAA records in that zone and its children. Wildcards do not create records. Other record types are left alone. With `IPV6` left false, AAAA records stay as they are.

A firewall source is an IPv4 or IPv6 address, a CIDR, a hostname, `current`, or `current6`. A hostname contributes one `/32` per A record and one `/128` per AAAA record. `current` is the IPv4 answer from `IP_ECHO_URL`. `current6` is the IPv6 answer and requires `IPV6=true`. IPv4 sources replace `srcCidr.ipv4` only, and IPv6 sources replace `srcCidr.ipv6` only. The other family is left as it is. Set exactly one of `FIREWALL_ID` or `FIREWALL_NAME`. Duplicate sources are dropped and the remaining order is kept.

`TLS_ROOTS=both` uses the embedded Mozilla roots and the image CA bundle. `webpki` uses only the embedded roots. `native` uses only the bundle.

IPv4 echo answers that are private, loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), or benchmarking (`198.18.0.0/15`) are skipped. IPv6 answers that are loopback, link-local, unique-local, documentation (`2001:db8::/32`), benchmarking (`2001:2::/48`), discard-only (`100::/64`), or IPv4-mapped are skipped.

## Image

The runtime image is a [Docker Hardened Image](https://docs.docker.com/dhi/), `dhi.io/static`, Debian 13. That base is not a Linux distribution you can log into. It has a CA certificate bundle, a `nonroot` user, and nothing else: no shell, no package manager, and no extra libraries.

The program is Rust, copied in as one statically linked musl binary. Published tags are multi-architecture manifests for `linux/amd64` and `linux/arm64`, so Apple Silicon and other arm64 hosts pull the arm64 image. A local `docker build` uses the machine's own architecture. The image also contains `/var/log/contabo-ddns`, owned by uid **65532** (gid 65532). That is the only path the process can write. A host bind mount has to be prepared with the `chown` or `setfacl` commands in [Run the published image](#run-the-published-image).

The healthcheck runs `/usr/local/bin/contabo-ddns health`. The image has no shell and no curl, so Docker calls the binary. It requests `GET /health` on `HEALTHCHECK_BIND` and expects the body `ok`.

Building the image pulls the builder and the runtime from `dhi.io`. That requires a free Docker Hub account:

```sh
docker login dhi.io
```

Podman uses `podman login dhi.io`. The published image is a normal image on GHCR and Docker Hub. Pulling `latest` or a version tag does not use `dhi.io`.

`docker exec` and `podman exec` cannot open a shell in this image. Read the container log, or the files in the log volume. Compose sets `init: true` because the image has no init process of its own. It also sets a read-only root filesystem, drops all capabilities, and sets `no-new-privileges`.

`TLS_ROOTS=both` uses the Mozilla roots built into the binary and the CA bundle from the image. `webpki` uses only the built-in roots. `native` uses only the bundle.

## Run

This builds from source. Pulling a published image is described above. Log in to `dhi.io` before the first build. From this directory, with `.env` in place:

```sh
podman compose up -d --build
```

Docker uses the same [compose.yaml](compose.yaml):

```sh
docker compose up -d --build
```

Compose names the image `contabo-ddns`, restarts it unless it is stopped, and mounts the `contabo-ddns-logs` volume on `/var/log/contabo-ddns`. `stop_grace_period` is 45 seconds, which is longer than one 30 second HTTP timeout.

A published image is `ghcr.io/mikelock-1991/contabo-ddns` and `docker.io/mikelockengineering/contabo-ddns`. `latest` tracks `main` and is also tagged with the `Cargo.toml` version, for example `0.1.4`. Every push to `dev`, including a merged pull request, publishes a new prerelease `0.1.4-beta.1`, `0.1.4-beta.2`, and so on. The moving tag for that series is `beta`. After `v0.1.4` exists on `main`, the next `dev` publish starts at `0.1.5-beta.1`. The deploy workflow logs in to Docker Hub with the `DOCKERHUB_USERNAME` variable and the `DOCKERHUB_TOKEN` secret (a Docker Hub access token with write access). Set both on the repository, or on the `main` and `dev` environments. The same credentials log in to `dhi.io` so the build can pull the hardened base. The finished image is pushed to Docker Hub and to GHCR. The deploy workflow signs each copy with Sigstore, using the GitHub Actions identity for `.github/workflows/deploy.yml`. No signing key is stored. Check a tag before running it:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mikelock-1991/contabo-ddns/\.github/workflows/deploy\.yml@' \
  ghcr.io/mikelock-1991/contabo-ddns:latest
```

The Docker Hub tag uses the same command with `docker.io/mikelockengineering/contabo-ddns:latest`.

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

A host bind mount uses the directory prepared above. On Podman with SELinux, add `:Z` so the directory can be relabeled:

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

Each cycle fetches the public IPv4 address, over IPv4 only, when DNS is on or a firewall rule uses `current`. With `IPV6=true` it fetches the same echo URLs over IPv6 only when DNS is on or a rule uses `current6`. DNS and the firewall then update in parallel.

Transient HTTP failures are retried up to three extra times, waiting 1 second, then 2, then 4. GET, PATCH, PUT, and the token request retry on timeouts, connection errors, 429, and 5xx. A DNS record POST retries only on 429, because a 5xx or a timeout may follow a create that already happened.

If the IPv4 lookup fails, A records are left unchanged and the cycle reports an error. AAAA records still update when the IPv6 lookup succeeded. The firewall still syncs unless one of its rules uses `current` and the IPv4 address is unknown, or `current6` and the IPv6 address is unknown.

The matching firewall rule's configured address family is replaced. A rule with only IPv4 sources leaves `srcCidr.ipv6` unchanged, and a rule with only IPv6 sources leaves `srcCidr.ipv4` unchanged. Other rules and unknown fields are copied through. If a rule name is missing, a hostname does not resolve, or the new source list would be empty, the firewall is not updated. A name lookup is cached until a GET for that id returns 404. A firewall PUT replaces the whole inbound rule list from the last GET, so a console edit made during that window can be overwritten.

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

---

Powered by https://ml-engineering.nl
