"""Local HTTPS Contabo/echo fixture and UDP/TCP DNS for the image smoke test."""

import ipaddress
import json
import os
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DNS_MODE = os.environ.get("DNS_MODE", "udp")
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "8443"))
TLS_DIR = os.environ.get("TLS_DIR", "/tls")
FIXTURE_IP = "192.0.2.2"
PUBLIC_IP = "203.0.113.10"
SOURCE_IPV6 = "2001:db8::10"
RECORDS = "/v1/dns/zones/example.test/records"
FIREWALL = "/v1/firewalls/ci-firewall"
HTTP_CALLS = set()
DNS_CALLS = set()
ERRORS = []
LOCK = threading.Lock()
EXPECTED_PATCH = {"ttl": 60, "prio": 0, "type": "A", "data": PUBLIC_IP}
EXPECTED_FIREWALL = {
    "rules": {
        "inbound": [{
            "displayName": "DNS smoke",
            "action": "accept",
            "srcCidr": {
                "ipv4": [f"{PUBLIC_IP}/32", "203.0.113.30/32"],
                "ipv6": [f"{SOURCE_IPV6}/128"],
            },
        }]
    }
}


def dns_reply(packet, protocol):
    """Answer just the two synthetic external names; Docker owns API aliases."""
    query_id, flags, questions, _, _, _ = struct.unpack("!6H", packet[:12])
    if questions != 1:
        raise ValueError("expected one DNS question")
    cursor = 12
    labels = []
    while packet[cursor]:
        size = packet[cursor]
        if size > 63:
            raise ValueError("unexpected compressed question")
        cursor += 1
        labels.append(packet[cursor:cursor + size].decode("ascii"))
        cursor += size
    cursor += 1
    kind, dns_class = struct.unpack("!HH", packet[cursor:cursor + 4])
    cursor += 4
    name = ".".join(labels).lower()
    known = name in {"echo.ddns.test", "source.ddns.test"}
    truncated = known and DNS_MODE == "tcp-fallback" and protocol == "udp"
    with LOCK:
        DNS_CALLS.add((protocol, name, kind))
    print(f"DNS {protocol} {name} type={kind} truncated={truncated}", flush=True)
    answer = b""
    address = None
    if known and dns_class == 1 and not truncated:
        if kind == 1:
            address = FIXTURE_IP if name == "echo.ddns.test" else PUBLIC_IP
        elif kind == 28 and name == "source.ddns.test":
            address = SOURCE_IPV6
    if address:
        data = ipaddress.ip_address(address).packed
        answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(data)) + data
    response_flags = 0x8480 | (flags & 0x0100) | (0 if known else 3)
    if truncated:
        response_flags |= 0x0200
    header = struct.pack("!6H", query_id, response_flags, 1, bool(answer), 0, 0)
    return header + packet[12:cursor] + answer


class UdpDns(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        sock.sendto(dns_reply(packet, "udp"), self.client_address)


class TcpDns(socketserver.StreamRequestHandler):
    def handle(self):
        while size := self.rfile.read(2):
            length, = struct.unpack("!H", size)
            reply = dns_reply(self.rfile.read(length), "tcp")
            self.wfile.write(struct.pack("!H", len(reply)) + reply)
            self.wfile.flush()


def assertion_errors():
    required_http = {
        ("POST", "/token"), ("GET", "/ip"), ("GET", "/v1/dns/zones"),
        ("GET", RECORDS), ("PATCH", f"{RECORDS}/1"),
        ("GET", FIREWALL), ("PUT", FIREWALL),
    }
    required_dns = {("echo.ddns.test", 1), ("source.ddns.test", 1), ("source.ddns.test", 28)}
    with LOCK:
        errors = list(ERRORS)
        errors += [f"missing HTTP {call}" for call in sorted(required_http - HTTP_CALLS)]
        for name, kind in sorted(required_dns):
            for protocol in (["udp", "tcp"] if DNS_MODE == "tcp-fallback" else ["udp"]):
                if (protocol, name, kind) not in DNS_CALLS:
                    errors.append(f"missing DNS {protocol} {name} type={kind}")
        if DNS_MODE == "udp" and any(call[0] == "tcp" for call in DNS_CALLS):
            errors.append("UDP case unexpectedly required TCP DNS")
    return errors


class Api(BaseHTTPRequestHandler):
    def respond(self, status, body):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_request(self):
        path = urllib.parse.urlsplit(self.path).path
        route = (self.command, path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if route == ("GET", "/health"):
            return self.respond(200, "ok")
        if route == ("GET", "/assert"):
            errors = assertion_errors()
            return self.respond(409 if errors else 200, {"errors": errors, "dns_mode": DNS_MODE})
        try:
            if path.startswith("/v1/") and self.headers.get("Authorization") != "Bearer ci-token":
                raise ValueError("missing fixture bearer token")
            if route == ("POST", "/token"):
                response = {"access_token": "ci-token", "expires_in": 3600}
            elif route == ("GET", "/ip"):
                response = PUBLIC_IP
            elif route == ("GET", "/v1/dns/zones"):
                response = {"data": [{"zoneName": "example.test"}]}
            elif route == ("GET", RECORDS):
                response = {"data": [{
                    "recordId": 1, "name": "home", "type": "A", "ttl": 60,
                    "prio": 0, "data": "198.51.100.20",
                }]}
            elif route == ("PATCH", f"{RECORDS}/1"):
                if json.loads(body) != EXPECTED_PATCH:
                    raise ValueError(f"unexpected DNS update: {body!r}")
                response = {"data": []}
            elif route == ("GET", FIREWALL):
                response = {"data": [{"rules": {"inbound": [{
                    "displayName": "DNS smoke", "action": "accept",
                    "srcCidr": {"ipv4": [], "ipv6": []},
                }]}}]}
            elif route == ("PUT", FIREWALL):
                if json.loads(body) != EXPECTED_FIREWALL:
                    raise ValueError(f"unexpected firewall sources: {body!r}")
                response = {"data": []}
            else:
                raise ValueError(f"unexpected HTTP route: {route}")
            with LOCK:
                HTTP_CALLS.add(route)
            self.respond(200, response)
        except (ValueError, TypeError) as err:
            with LOCK:
                ERRORS.append(str(err))
            self.respond(422, {"error": str(err)})

    do_GET = handle_request
    do_POST = handle_request
    do_PATCH = handle_request
    do_PUT = handle_request


def serve():
    udp = socketserver.ThreadingUDPServer(("0.0.0.0", DNS_PORT), UdpDns)
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", DNS_PORT), TcpDns)
    udp.daemon_threads = tcp.daemon_threads = True
    api = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), Api)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(f"{TLS_DIR}/server.crt", f"{TLS_DIR}/server.key")
    api.socket = tls.wrap_socket(api.socket, server_side=True)
    for server in (udp, tcp):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Fixture ready: DNS={DNS_MODE}, HTTPS=:{HTTPS_PORT}", flush=True)
    api.serve_forever()


def probe(mode):
    tls = ssl.create_default_context(cafile=f"{TLS_DIR}/ca.crt")
    url = f"https://localhost:{HTTPS_PORT}/{'health' if mode == 'wait' else 'assert'}"
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(url, context=tls, timeout=2) as response:
                print(response.read().decode())
            return
        except urllib.error.HTTPError as err:
            raise SystemExit(err.read().decode()) from err
        except (OSError, urllib.error.URLError):
            if mode != "wait" or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    elif sys.argv[1] in {"wait", "assert"}:
        probe(sys.argv[1])
    else:
        raise SystemExit("usage: fixture.py serve|wait|assert")
