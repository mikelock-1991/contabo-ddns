#!/usr/bin/env bash
# Run the production image against local HTTPS and DNS fixtures on Linux.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'This smoke test requires a rootful Linux Docker host (including macvlan).' >&2
  exit 1
fi

image=${1:-contabo-ddns:ci}
fixture_image=${SMOKE_FIXTURE_IMAGE:-python:3.14.10-slim}
fixture_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
prefix="ddns-ci-$$"
network="$prefix-net"
fixture="$prefix-fixture"
app="$prefix-app"
parent="ddns-ci-$RANDOM"
parent_created=false
ip_command=(ip)
if (( EUID != 0 )); then
  ip_command=(sudo ip)
fi

cleanup_case() {
  docker rm --force "$app" "$fixture" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ $parent_created == true ]]; then
    "${ip_command[@]}" link delete "$parent" || true
    parent_created=false
  fi
}

cleanup() {
  local status=$?
  if (( status != 0 )); then
    docker logs "$app" 2>&1 || true
    docker logs "$fixture" 2>&1 || true
    docker network inspect "$network" 2>&1 || true
  fi
  cleanup_case
  rm -rf "${scratch:?}"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A separate CA and leaf certificate exercise TLS verification in the image.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=contabo-ddns-ci-ca \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$scratch/ca.key" -out "$scratch/ca.crt" 2>"$scratch/openssl.log"
openssl req -newkey rsa:2048 -nodes -subj /CN=api.ddns.test \
  -keyout "$scratch/server.key" -out "$scratch/server.csr" 2>>"$scratch/openssl.log"
cat >"$scratch/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.ddns.test,DNS:auth.ddns.test,DNS:echo.ddns.test,DNS:localhost
EOF
openssl x509 -req -in "$scratch/server.csr" -CA "$scratch/ca.crt" \
  -CAkey "$scratch/ca.key" -CAcreateserial -days 1 -sha256 \
  -extfile "$scratch/server.ext" -out "$scratch/server.crt" 2>>"$scratch/openssl.log"
chmod 755 "$scratch"
# The capability-stripped fixture runs as a different uid from the runner.
# This key is generated for this isolated test and discarded during cleanup.
chmod 644 "$scratch/ca.crt" "$scratch/server.crt" "$scratch/server.key"

image_user=$(docker image inspect --format '{{.Config.User}}' "$image")
[[ $image_user == 65532:65532 ]]
docker pull "$fixture_image"

for driver in bridge macvlan; do
  for dns_mode in udp tcp-fallback; do
    for config_mode in system unreadable; do
      echo "Testing $driver network with $dns_mode DNS and $config_mode configuration"
      options=(--driver "$driver" --subnet 192.0.2.0/24 --gateway 192.0.2.1)
      if [[ $driver == macvlan ]]; then
        # A real parent keeps Docker's upstream DNS forwarding enabled. A
        # parentless macvlan is internal and would not exercise that path.
        "${ip_command[@]}" link add "$parent" type dummy
        parent_created=true
        "${ip_command[@]}" link set "$parent" up
        options+=(-o "parent=$parent" -o macvlan_mode=bridge)
      fi
      docker network create "${options[@]}" "$network"
      docker run --detach --name "$fixture" --init --read-only \
        --cap-drop ALL --cap-add NET_BIND_SERVICE \
        --network "$network" --ip 192.0.2.2 \
        --network-alias api.ddns.test --network-alias auth.ddns.test \
        --mount "type=bind,src=$fixture_dir,dst=/fixture,readonly" \
        --mount "type=bind,src=$scratch,dst=/tls,readonly" \
        --env PYTHONDONTWRITEBYTECODE=1 --env "DNS_MODE=$dns_mode" \
        "$fixture_image" python -u /fixture/fixture.py serve
      timeout 30s docker exec "$fixture" python /fixture/fixture.py wait

      # CI's upstream DNS points at the fixture. Docker configures its usual
      # 127.0.0.11 stub; the unreadable case masks only its configuration file.
      configuration_options=()
      if [[ $config_mode == unreadable ]]; then
        # Reproduce a resolver file that the image's uid 65532 cannot read.
        # This CI-only mount does not change Docker's nameserver or forwarding.
        printf 'nameserver 127.0.0.11\n' >"$scratch/unreadable-resolv.conf"
        chmod 600 "$scratch/unreadable-resolv.conf"
        configuration_options+=(--mount "type=bind,src=$scratch/unreadable-resolv.conf,dst=/etc/resolv.conf,readonly")
      fi
      docker create --name "$app" --init --read-only --cap-drop ALL "${configuration_options[@]}" \
        --security-opt no-new-privileges:true --network "$network" --dns 192.0.2.2 \
        --add-host hosts.ddns.test:203.0.113.30 \
        --mount "type=bind,src=$scratch/ca.crt,dst=/ci-ca.crt,readonly" \
        --env SSL_CERT_FILE=/ci-ca.crt --env SSL_CERT_DIR=/nonexistent \
        --env TLS_ROOTS=native --env LOG_DIR= --env INTERVAL_SECONDS=0 \
        --env RUN_ON_START=true --env DRY_RUN=false --env IPV6=false \
        --env CONTABO_CLIENT_ID=ci --env CONTABO_CLIENT_SECRET=ci \
        --env CONTABO_API_USER=ci@example.test --env CONTABO_API_PASSWORD=ci \
        --env CONTABO_API_BASE=https://api.ddns.test:8443 \
        --env CONTABO_AUTH_URL=https://auth.ddns.test:8443/token \
        --env IP_ECHO_URL=https://echo.ddns.test:8443/ip \
        --env IP_ECHO_TIMEOUT_SECONDS=10 --env DNS_RECORDS=home.example.test \
        --env FIREWALL_ID=ci-firewall \
        --env 'FIREWALL_RULES=[{"displayName":"DNS smoke","sources":["source.ddns.test","hosts.ddns.test"]}]' \
        "$image"
      docker start "$app"
      status=$(timeout 90s docker wait "$app")
      docker logs "$app"
      [[ $status == 0 ]]
      if [[ $config_mode == unreadable ]]; then
        docker logs "$app" 2>&1 | awk '
          /cannot read \/etc\/resolv.conf; using Docker DNS/ { found=1 }
          END { exit !found }
        '
      fi
      docker cp "$app:/etc/resolv.conf" "$scratch/resolv.conf"
      cat "$scratch/resolv.conf"
      awk '$1 == "nameserver" && $2 == "127.0.0.11" { found=1 } END { exit !found }' \
        "$scratch/resolv.conf"
      docker exec "$fixture" python /fixture/fixture.py assert
      cleanup_case
    done
  done
done
