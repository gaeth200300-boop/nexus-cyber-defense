"""Lab fixture files — real artifacts the platform's own engines analyze.

Nothing here is fake telemetry: the log excerpts are training fixtures whose
lines are parsed by the same log engine that processes production logs, the PCAP
is a real capture file written with dpkt, and the certificate is a genuine
(expired, weak-key) X.509 certificate. Fixtures are written to
`storage/labs/` on seed and are safe to delete/regenerate at any time.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime
from pathlib import Path

from ..config import settings

log = logging.getLogger("nexus.labs.files")

# ---------------------------------------------------------------------------
# Text fixtures
# ---------------------------------------------------------------------------
NGINX_ACCESS_LOG = """\
198.51.100.23 - - [11/Jan/2026:03:12:44 +0000] "GET /product?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
198.51.100.23 - - [11/Jan/2026:03:12:45 +0000] "GET /product?id=2'%20OR%20'1'='1 HTTP/1.1" 500 512 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
198.51.100.23 - - [11/Jan/2026:03:12:46 +0000] "GET /item.php?cat=1%20AND%20SLEEP(5) HTTP/1.1" 200 1024 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
198.51.100.23 - - [11/Jan/2026:03:12:47 +0000] "GET /search?q=information_schema.tables HTTP/1.1" 200 980 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
198.51.100.23 - - [11/Jan/2026:03:13:02 +0000] "GET /.env HTTP/1.1" 403 180 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:13:03 +0000] "GET /.git/config HTTP/1.1" 403 180 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:13:04 +0000] "GET /wp-admin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:13:05 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:13:06 +0000] "GET /.ssh/id_rsa HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:13:07 +0000] "GET /backup/db.sql.gz HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
198.51.100.23 - - [11/Jan/2026:03:14:01 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:02 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:03 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:04 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:05 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:06 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:07 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:08 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:09 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:10 +0000] "POST /login HTTP/1.1" 401 96 "-" "curl/8.5.0"
198.51.100.23 - - [11/Jan/2026:03:14:11 +0000] "POST /login HTTP/1.1" 200 640 "-" "curl/8.5.0"
203.0.113.9 - - [11/Jan/2026:04:00:12 +0000] "GET / HTTP/1.1" 200 15432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
203.0.113.9 - - [11/Jan/2026:04:00:13 +0000] "GET /assets/app.css HTTP/1.1" 200 8123 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"
"""

APP_ERRORS_JSON = """\
{"ts": "2026-01-11T03:20:01Z", "level": "ERROR", "service": "billing-api", "message": "database connection failed: password=hunter2 host=db-prod-01 timeout=5s"}
{"ts": "2026-01-11T03:20:02Z", "level": "ERROR", "service": "billing-api", "message": "database connection failed: password=hunter2 host=db-prod-01 timeout=5s"}
{"ts": "2026-01-11T03:20:03Z", "level": "WARN", "service": "billing-api", "message": "retry 1/3 for invoice worker"}
{"ts": "2026-01-11T03:20:04Z", "level": "ERROR", "service": "auth-service", "message": "JWT validation failed: api_key=sk_live_51H8xQ2eZvKYlo2C9oV for user u-2291"}
{"ts": "2026-01-11T03:21:10Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:21:11Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:21:12Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:21:13Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:21:14Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:21:15Z", "level": "ERROR", "service": "checkout", "message": "HTTP 500 upstream timeout calling payments-gateway"}
{"ts": "2026-01-11T03:22:00Z", "level": "INFO", "service": "checkout", "message": "circuit breaker opened for payments-gateway after 6 failures"}
"""

CAPTURED_HEADERS = """\
# Training fixture: real HTTP response headers captured from an assessment
# (identifiers anonymized). Parse these as if you had intercepted the response.
HTTPS GET https://shop.example.com/account
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 11 Jan 2026 03:30:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 18422
Connection: keep-alive
Set-Cookie: session=8f2b1c9d4e6a7b3c5d8e9f0a1b2c3d4e; Path=/; Max-Age=86400
Set-Cookie: theme=dark; Path=/
X-Powered-By: Express
Cache-Control: no-store
"""

# ---------------------------------------------------------------------------
# PCAP fixture (written with dpkt at seed time)
# ---------------------------------------------------------------------------
PCAP_FILE = "lab_traffic.pcap"
TLS_CERT_FILE = "lab_legacy_cert.pem"


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _ip(text: str) -> bytes:
    return socket.inet_aton(text)


def _build_pcap(target: Path) -> None:
    import dpkt

    base_ts = 1768100000.0  # fixed timestamp: fixtures must be deterministic
    packets: list[tuple[float, bytes]] = []

    def add_eth_ip(src: str, dst: str, proto: int, payload: bytes, src_mac: str = "00:11:22:33:44:55", dst_mac: str = "66:77:88:99:aa:bb") -> bytes:
        ip_layer = dpkt.ip.IP(src=_ip(src), dst=_ip(dst), p=proto, ttl=64, data=payload)
        ip_layer.len = len(ip_layer)
        return bytes(dpkt.ethernet.Ethernet(src=_mac(src_mac), dst=_mac(dst_mac), type=dpkt.ethernet.ETH_TYPE_IP, data=ip_layer))

    def udp_dns_query(src: str, dport: int, query: str, dns_id: int) -> bytes:
        dns = dpkt.dns.DNS(id=dns_id, qd=[dpkt.dns.DNS.Q(name=query, type=dpkt.dns.DNS_A)])
        dns.qr = dpkt.dns.DNS_Q
        udp_layer = dpkt.udp.UDP(sport=54000 + (dns_id % 100), dport=dport, data=bytes(dns))
        udp_layer.ulen = len(udp_layer)
        return add_eth_ip(src, "10.20.30.53", dpkt.ip.IP_PROTO_UDP, bytes(udp_layer))

    def tcp_http(src: str, dst: str, sport: int, payload: bytes, dport: int = 80) -> bytes:
        tcp_layer = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, win=64240, data=payload)
        tcp_layer.off = 5
        return add_eth_ip(src, dst, dpkt.ip.IP_PROTO_TCP, bytes(tcp_layer))

    # 1) DNS tunnelling: long high-entropy labels to a suspicious TLD
    tunnel_domains = [
        "aGVsbG9fZXhmaWx0cmF0aW9uX2NoYW5rZWxfMDAx.cmVjZWl2ZS1kYXRh.ewogICAiY21kIjoicHdkIgp9.c2VjcmV0LOUT.exfil-node1.tk",
        "dGhpcy1sb29rcy1saWtlLWJhc2U2NC1lbmNvZGVkLWRucy10dW5uZWxpbmctcGF5bG9hZA.aW5mb3JtYXRpb24tYmFzZS5leGZpbA.d2l0aC1sb25nLWxhYmVscy5kYXRh.exfil-node1.tk",
        "c2Vjb25kLXNhbXBsZS1vZi1lbmNvZGVkLXRyYWZmaWM.cmVjZWl2ZS1kYXRh.endpoint-probe.tk",
    ]
    for index, domain in enumerate(tunnel_domains):
        packets.append((base_ts + index, udp_dns_query("10.20.30.40", 53, domain, 4000 + index)))

    # 2) Cleartext credentials: HTTP Basic auth + form login over plain HTTP
    basic_request = (
        b"GET /admin/export?format=csv HTTP/1.1\r\n"
        b"Host: reports.internal.example\r\n"
        b"Authorization: Basic YWRtaW46U3VwZXJTZWNyZXQhMjAyNg==\r\n"
        b"User-Agent: curl/8.5.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    packets.append((base_ts + 10, tcp_http("10.20.30.40", "10.20.30.80", 51515, basic_request)))
    form_login = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: portal.internal.example\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 33\r\n\r\n"
        b"username=admin password=Winter2026!"
    )
    packets.append((base_ts + 11, tcp_http("10.20.30.40", "10.20.30.81", 51516, form_login)))

    # 3) ARP conflict: two different MACs claim 10.20.30.40 (spoofing / MITM)
    import dpkt.arp

    for offset, mac in enumerate(("aa:bb:cc:00:00:01", "de:ad:be:ef:00:99")):
        arp = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REPLY,
            sha=_mac(mac),
            spa=_ip("10.20.30.40"),
            tha=_mac("00:11:22:33:44:55"),
            tpa=_ip("10.20.30.30"),
        )
        eth = dpkt.ethernet.Ethernet(src=_mac(mac), dst=_mac("00:11:22:33:44:55"), type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
        packets.append((base_ts + 20 + offset, bytes(eth)))

    with target.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for ts, data in packets:
            writer.writepkt(data, ts=ts)


# ---------------------------------------------------------------------------
# Legacy TLS certificate fixture (real X.509, RSA-1024, expired)
# ---------------------------------------------------------------------------
def _build_certificate(target: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Legacy Internal Services (training fixture)"),
            x509.NameAttribute(NameOID.COMMON_NAME, "legacy-portal.internal.example"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x4E45585553)  # "NEXUS" — deterministic
        .not_valid_before(datetime(2020, 1, 1, 0, 0, 0))
        .not_valid_after(datetime(2021, 1, 1, 0, 0, 0))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("legacy-portal.internal.example"), x509.DNSName("old-vpn.internal.example")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    target.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
TEXT_FIXTURES = {
    "lab_nginx_access.log": NGINX_ACCESS_LOG,
    "lab_app_errors.json": APP_ERRORS_JSON,
    "lab_captured_headers.txt": CAPTURED_HEADERS,
}


def labs_dir() -> Path:
    path = settings.data_path / "labs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_lab_files(*, force: bool = False) -> dict[str, Path]:
    """Write every lab fixture once; returns {name: path}."""
    directory = labs_dir()
    written: dict[str, Path] = {}

    for name, content in TEXT_FIXTURES.items():
        path = directory / name
        if force or not path.exists():
            path.write_text(content, encoding="utf-8")
        written[name] = path

    pcap_path = directory / PCAP_FILE
    if force or not pcap_path.exists():
        try:
            _build_pcap(pcap_path)
        except Exception as exc:  # pragma: no cover - defensive
            log.error("could not build lab pcap: %s", exc)
        written[PCAP_FILE] = pcap_path
    else:
        written[PCAP_FILE] = pcap_path

    cert_path = directory / TLS_CERT_FILE
    if force or not cert_path.exists():
        _build_certificate(cert_path)
    written[TLS_CERT_FILE] = cert_path
    return written
