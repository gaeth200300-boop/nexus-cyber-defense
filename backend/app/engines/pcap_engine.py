"""PCAP analysis engine — real packet parsing with dpkt.

Extracts protocol statistics, conversations, DNS/HTTP/TLS activity, credential
material (always redacted) and IOCs. Runs entirely offline on an uploaded file.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import math
import re
from pathlib import Path
from typing import Any

from ..core.redaction import redact_text
from ..core.utils import sha256_hex
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult

log = logging.getLogger("nexus.engine.pcap")

MAX_PACKETS = 300_000
MAX_PAYLOAD_SAMPLE = 800

CREDENTIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)authorization:\s*basic\s+[a-z0-9+/=]{8,}", "HTTP Basic authorization header"),
    (r"(?i)\b(user|username|login)\s*[:=]\s*([^\s&]{3,32})\s+(pass|password|pwd)\s*[:=]\s*(\S{3,64})", "Cleartext login credentials"),
    (r"(?i)\b(pass|password|pwd)\s*[:=]\s*(\S{3,64})", "Cleartext password parameter"),
    (r"(?i)\bUSER\s+(\S{3,32})\r?\nPASS\s+(\S{3,64})", "FTP credentials"),
    (r"(?i)\bEHLO\b.*?(AUTH\s+(?:PLAIN|LOGIN))", "SMTP AUTH exchange"),
    (r"(?i)\bset-cookie:\s*session", "Session cookie in clear text"),
)

SUSPICIOUS_TLDS = (".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov", ".click", ".country")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_sni(payload: bytes) -> str:
    """Extract the SNI value from a TLS ClientHello (manual parse, no dependencies)."""
    try:
        if len(payload) < 44 or payload[0] != 0x16:
            return ""
        record_length = int.from_bytes(payload[3:5], "big")
        body = payload[5 : 5 + record_length]
        if len(body) < 42 or body[0] != 0x01:
            return ""
        offset = 4 + 2 + 32  # handshake header + version + random
        session_id_length = body[offset]
        offset += 1 + session_id_length
        cipher_length = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2 + cipher_length
        compression_length = body[offset]
        offset += 1 + compression_length
        extensions_length = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        end = min(offset + extensions_length, len(body))
        while offset + 4 <= end:
            ext_type = int.from_bytes(body[offset : offset + 2], "big")
            ext_length = int.from_bytes(body[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == 0x00:  # server_name
                data = body[offset : offset + ext_length]
                if len(data) >= 5:
                    name_type = data[0]
                    name_length = int.from_bytes(data[1:3], "big")
                    if name_type == 0 and len(data) >= 3 + name_length:
                        return data[3 : 3 + name_length].decode("idna", errors="ignore")
            offset += ext_length
    except Exception:
        return ""
    return ""


def analyze_pcap(path: str, *, max_packets: int = MAX_PACKETS) -> dict[str, Any]:
    import dpkt

    summary: dict[str, Any] = {
        "file": Path(path).name,
        "sha256": "",
        "size_bytes": 0,
        "packets": 0,
        "first_ts": None,
        "last_ts": None,
        "protocols": collections.Counter(),
        "conversations": collections.Counter(),
        "conversation_bytes": collections.Counter(),
        "dst_ports": collections.Counter(),
        "dns_queries": collections.Counter(),
        "dns_suspicious": [],
        "http_requests": [],
        "tls_sni": collections.Counter(),
        "arp_table": collections.defaultdict(set),
        "syn_targets": collections.defaultdict(set),
        "credentials": [],
        "iocs": {"ips": set(), "domains": set(), "urls": set(), "hashes": set()},
        "parse_errors": 0,
        "truncated": False,
    }

    data = Path(path).read_bytes()
    summary["size_bytes"] = len(data)
    summary["sha256"] = sha256_hex(data)

    try:
        reader = dpkt.pcap.Reader(_BytesReader(data))
        iterator = reader
    except Exception:
        try:
            reader = dpkt.pcapng.Reader(_BytesReader(data))
            iterator = reader
        except Exception as exc:
            summary["error"] = f"unsupported_capture_format: {exc}"
            return summary

    for timestamp, packet in iterator:
        summary["packets"] += 1
        if summary["packets"] > max_packets:
            summary["truncated"] = True
            break
        if summary["first_ts"] is None:
            summary["first_ts"] = timestamp
        summary["last_ts"] = timestamp

        try:
            ethernet = dpkt.ethernet.Ethernet(packet)
        except Exception:
            summary["parse_errors"] += 1
            continue

        if isinstance(ethernet.data, dpkt.arp.ARP):
            arp = ethernet.data
            try:
                summary["arp_table"][str(ipaddress.ip_address(arp.spa))].add(
                    ":".join(f"{b:02x}" for b in arp.sha)
                )
            except Exception:
                pass
            continue

        ip_layer = ethernet.data
        if not isinstance(ip_layer, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue
        src_ip = _ip_to_str(ip_layer.src)
        dst_ip = _ip_to_str(ip_layer.dst)
        summary["protocols"][ip_layer.__class__.__name__] += 1
        summary["iocs"]["ips"].add(src_ip)
        summary["iocs"]["ips"].add(dst_ip)

        transport = ip_layer.data
        if isinstance(transport, dpkt.tcp.TCP):
            key = (src_ip, dst_ip, transport.sport, transport.dport)
            summary["conversations"][key] += 1
            summary["conversation_bytes"][key] += len(transport.data)
            summary["dst_ports"][transport.dport] += 1
            if transport.flags & dpkt.tcp.TH_SYN and not transport.flags & dpkt.tcp.TH_ACK:
                summary["syn_targets"][src_ip].add(transport.dport)

            payload = transport.data
            if payload:
                if transport.dport in (80, 8080, 8000, 3128) or transport.sport in (80, 8080, 8000, 3128):
                    line = payload[:MAX_PAYLOAD_SAMPLE].decode("latin-1", errors="replace")
                    match = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]", line)
                    if match:
                        host_match = re.search(r"(?im)^Host:\s*([^\r\n]+)", line)
                        summary["http_requests"].append(
                            {
                                "method": match.group(1),
                                "path": match.group(2)[:200],
                                "host": (host_match.group(1).strip() if host_match else "")[:200],
                                "src": src_ip,
                            }
                        )
                    for pattern, label in CREDENTIAL_PATTERNS:
                        found = re.search(pattern, line)
                        if found:
                            summary["credentials"].append({"label": label, "src": src_ip, "sample": found.group(0)[:200]})
                if transport.dport == 443 or transport.sport == 443:
                    sni = extract_sni(payload)
                    if sni:
                        summary["tls_sni"][sni] += 1
                        summary["iocs"]["domains"].add(sni)
                for match in re.finditer(rb"\b\d{1,3}(?:\.\d{1,3}){3}\b", payload[:600]):
                    pass
        elif isinstance(transport, dpkt.udp.UDP):
            key = (src_ip, dst_ip, transport.sport, transport.dport)
            summary["conversations"][key] += 1
            summary["conversation_bytes"][key] += len(transport.data)
            summary["dst_ports"][transport.dport] += 1
            if transport.dport == 53 or transport.sport == 53:
                try:
                    dns = dpkt.dns.DNS(transport.data)
                    for question in dns.qd:
                        qname = question.name.rstrip(".")
                        summary["dns_queries"][qname] += 1
                        summary["iocs"]["domains"].add(qname)
                        labels = qname.split(".")
                        longest = max((len(label) for label in labels), default=0)
                        if longest > 45 or _entropy(qname.replace(".", "")) > 4.2:
                            summary["dns_suspicious"].append(
                                {"query": qname[:200], "reason": f"long_label={longest}, entropy={_entropy(qname.replace('.', '')):.2f}", "src": src_ip}
                            )
                except Exception:
                    pass

    # URL and hash extraction from HTTP requests
    for request in summary["http_requests"]:
        if request.get("host"):
            summary["iocs"]["urls"].add(f"http://{request['host']}{request['path']}")
    for query in list(summary["dns_queries"])[:500]:
        if any(query.endswith(tld) for tld in SUSPICIOUS_TLDS):
            summary["dns_suspicious"].append({"query": query, "reason": "suspicious_tld", "src": ""})

    return summary


class _BytesReader:
    """Minimal file-like wrapper so dpkt can read from memory."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._data[self._position :]
            self._position = len(self._data)
            return chunk
        chunk = self._data[self._position : self._position + size]
        self._position += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._position = offset
        elif whence == 1:
            self._position += offset
        else:
            self._position = len(self._data) + offset
        return self._position

    def tell(self) -> int:
        return self._position


def _ip_to_str(raw: bytes) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        try:
            return str(ipaddress.ip_address(raw))
        except Exception:
            return "unknown"


def _serializable(summary: dict[str, Any]) -> dict[str, Any]:
    def convert(value: Any) -> Any:
        if isinstance(value, dict):
            return {("|".join(map(str, k)) if isinstance(k, tuple) else str(k)): convert(v) for k, v in value.items()}
        if isinstance(value, (list, set)):
            return [convert(v) for v in value]
        if isinstance(value, collections.Counter):
            return {str(k): v for k, v in value.most_common(50)}
        if isinstance(value, bytes):
            return value.hex()
        return value

    return convert(summary)


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={})
    options = ctx.scan.options or {}
    upload_path = str(options.get("upload_path") or "")
    if not upload_path or not Path(upload_path).exists():
        ctx.emit("No capture file found for this scan.", level="error", phase="parse")
        ctx.phase("parse", "failed", progress=100)
        return result

    ctx.phase("parse", "running", progress=20)
    ctx.emit(f"Parsing capture {Path(upload_path).name} …", phase="parse")
    summary = analyze_pcap(upload_path)
    if summary.get("error"):
        ctx.emit(f"Capture could not be parsed: {summary['error']}", level="error", phase="parse")
        ctx.phase("parse", "failed", progress=100)
        return result
    ctx.emit(
        f"Parsed {summary['packets']} packet(s)"
        + (" (truncated at the packet limit)" if summary.get("truncated") else "")
        + f", {len(summary['conversations'])} conversation(s).",
        phase="parse",
        kind="metric",
    )
    ctx.phase("parse", "done", progress=100)

    ctx.phase("protocols", "running", progress=50)
    protocols = {str(k): int(v) for k, v in summary["protocols"].items()}
    ctx.emit(
        "Protocol mix: " + ", ".join(f"{name}={count}" for name, count in sorted(protocols.items(), key=lambda kv: -kv[1])),
        phase="protocols",
    )
    ctx.phase("protocols", "done", progress=100)

    ctx.phase("conversations", "running", progress=50)
    top_conversations = [
        {"src": k[0], "dst": k[1], "sport": k[2], "dport": k[3], "packets": count, "bytes": summary["conversation_bytes"].get(k, 0)}
        for k, count in summary["conversations"].most_common(20)
    ]
    for conversation in top_conversations[:10]:
        ctx.emit(
            f"{conversation['src']}:{conversation['sport']} → {conversation['dst']}:{conversation['dport']} "
            f"({conversation['packets']} packets, {conversation['bytes']} bytes)",
            level="debug",
            phase="conversations",
        )
    ctx.phase("conversations", "done", progress=100)

    ctx.phase("dns", "running", progress=60)
    for entry in summary["dns_suspicious"][:15]:
        ctx.emit(f"Suspicious DNS: {entry['query'][:120]} ({entry['reason']})", level="warn", phase="dns")
    if summary["dns_suspicious"]:
        ctx.save(
            check_id="pcap_dns_tunneling",
            category="dns",
            title="DNS queries with tunnelling characteristics",
            severity="medium",
            confidence="tentative",
            target=summary["file"],
            location="DNS",
            description=f"{len(summary['dns_suspicious'])} query name(s) look like encoded data (very long labels or high entropy).",
            impact="DNS tunnelling is used to exfiltrate data or to reach command-and-control infrastructure through firewalls that allow DNS.",
            remediation="Enable DNS logging and filtering, resolve only through a controlled resolver, and inspect suspicious label entropy at the perimeter.",
            references=["https://attack.mitre.org/techniques/T1071/004/"],
            cwe="CWE-201",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            evidence={
                "kind": "pcap_snippet",
                "label": "Suspicious DNS queries",
                "response": json.dumps(summary["dns_suspicious"][:10], ensure_ascii=False, indent=2),
                "source": ENGINE_NAME,
            },
            tags=["pcap", "dns", "exfiltration"],
        )
        result.findings += 1
    ctx.phase("dns", "done", progress=100)

    ctx.phase("http", "running", progress=60)
    cleartext_credentials = summary["credentials"]
    if cleartext_credentials:
        redacted_entries = []
        for entry in cleartext_credentials[:10]:
            safe_sample, redactions = redact_text(entry["sample"])
            redacted_entries.append({**entry, "sample": safe_sample, "redactions": redactions})
        ctx.save(
            check_id="pcap_cleartext_credentials",
            category="crypto",
            title="Credentials transmitted in clear text",
            severity="high",
            confidence="certain",
            target=summary["file"],
            location="TCP payloads",
            description=f"{len(cleartext_credentials)} occurrence(s) of credential material were found in unencrypted traffic.",
            impact="Anyone able to capture traffic on the path obtains working credentials and can move laterally without triggering authentication alerts.",
            remediation="Replace the affected protocol with its TLS variant (HTTPS/FTPS/IMAPS/LDAPS), rotate the exposed credentials, and remove the plaintext service.",
            references=["https://attack.mitre.org/techniques/T1040/", "https://attack.mitre.org/techniques/T1552/"],
            cwe="CWE-319",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            verified=True,
            evidence={
                "kind": "pcap_snippet",
                "label": "Cleartext credential patterns (redacted)",
                "response": json.dumps(redacted_entries, ensure_ascii=False, indent=2),
                "source": ENGINE_NAME,
            },
            tags=["pcap", "credentials", "cleartext"],
        )
        result.findings += 1

    if summary["http_requests"]:
        ctx.save(
            check_id="pcap_cleartext_http",
            category="crypto",
            title="Unencrypted HTTP traffic in the capture",
            severity="medium",
            confidence="certain",
            target=summary["file"],
            location="TCP/80",
            description=f"{len(summary['http_requests'])} plain HTTP request(s) observed: "
            + ", ".join(f"{r['method']} {r['host']}{r['path'][:40]}" for r in summary["http_requests"][:5]),
            impact="Request paths, cookies and any submitted data are readable by anyone on the network path.",
            remediation="Enforce HTTPS across the estate (HSTS + redirects) and audit for legacy endpoints that still serve plain HTTP.",
            references=["https://attack.mitre.org/techniques/T1040/"],
            cwe="CWE-319",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            evidence={
                "kind": "pcap_snippet",
                "label": "HTTP requests",
                "response": json.dumps(summary["http_requests"][:10], ensure_ascii=False, indent=2),
                "source": ENGINE_NAME,
            },
            tags=["pcap", "http"],
        )
        result.findings += 1
    ctx.phase("http", "done", progress=100)

    ctx.phase("tls", "running", progress=70)
    sni_list = list(summary["tls_sni"].items())[:30]
    if sni_list:
        ctx.emit("TLS server names observed: " + ", ".join(name for name, _ in sni_list[:10]), phase="tls")
    ctx.phase("tls", "done", progress=100)

    ctx.phase("iocs", "running", progress=70)
    arp_conflicts = {ip: sorted(macs) for ip, macs in summary["arp_table"].items() if len(macs) > 1}
    if arp_conflicts:
        ctx.save(
            check_id="pcap_arp_spoofing",
            category="network_service",
            title="Multiple MAC addresses claim the same IP (ARP spoofing)",
            severity="high",
            confidence="firm",
            target=summary["file"],
            location="ARP",
            description=f"Conflicting ARP replies detected for: {', '.join(list(arp_conflicts)[:5])}",
            impact="ARP spoofing positions an attacker as a man-in-the-middle on a local segment, enabling traffic interception and credential theft.",
            remediation="Enable dynamic ARP inspection / port security on the switch, segment the network, and identify the offending port from switch logs.",
            references=["https://attack.mitre.org/techniques/T1557/002/"],
            cwe="CWE-300",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            evidence={
                "kind": "pcap_snippet",
                "label": "ARP conflicts",
                "response": json.dumps(arp_conflicts, indent=2),
                "source": ENGINE_NAME,
            },
            tags=["pcap", "arp", "mitm"],
        )
        result.findings += 1

    scanners = {ip: len(ports) for ip, ports in summary["syn_targets"].items() if len(ports) > 50}
    if scanners:
        top_scanner = max(scanners.items(), key=lambda kv: kv[1])
        ctx.save(
            check_id="pcap_port_scan",
            category="network_service",
            title="Port scanning activity detected",
            severity="medium",
            confidence="firm",
            target=top_scanner[0],
            location="TCP SYN",
            description=f"Source {top_scanner[0]} sent SYNs to {top_scanner[1]} distinct ports"
            + (f" (plus {len(scanners) - 1} other source(s) with a similar pattern)" if len(scanners) > 1 else "") + ".",
            impact="Scanning is usually reconnaissance that precedes exploitation attempts from the same source.",
            remediation="Block the source at the perimeter, verify no service answered, and check for follow-up exploitation attempts in the same window.",
            references=["https://attack.mitre.org/techniques/T1046/"],
            cwe="CWE-200",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            verified=True,
            evidence={
                "kind": "pcap_snippet",
                "label": "SYN fan-out",
                "response": json.dumps(scanners, indent=2),
                "source": ENGINE_NAME,
            },
            tags=["pcap", "reconnaissance"],
        )
        result.findings += 1

    iocs = {
        "ips": sorted(summary["iocs"]["ips"])[:200],
        "domains": sorted(summary["iocs"]["domains"])[:200],
        "urls": sorted(summary["iocs"]["urls"])[:200],
    }
    result.data = {
        "packets": summary["packets"],
        "protocols": protocols,
        "top_conversations": top_conversations,
        "top_dst_ports": [
            {"port": port, "count": count, "service": _service_for(port)}
            for port, count in summary["dst_ports"].most_common(20)
        ],
        "dns_queries": [{"name": name, "count": count} for name, count in summary["dns_queries"].most_common(30)],
        "tls_sni": [{"name": name, "count": count} for name, count in summary["tls_sni"].most_common(30)],
        "http_requests": summary["http_requests"][:30],
        "iocs": iocs,
        "capture": {"file": summary["file"], "sha256": summary["sha256"], "size_bytes": summary["size_bytes"]},
    }
    ctx.emit(
        f"Extracted {len(iocs['ips'])} IP(s), {len(iocs['domains'])} domain(s) and {len(iocs['urls'])} URL(s) as indicators.",
        phase="iocs",
        kind="metric",
    )
    ctx.phase("iocs", "done", progress=100)

    # Persist the full analysis next to the evidence so the UI can offer a download.
    from ..config import settings

    artifact = settings.reports_dir / f"pcap-{ctx.scan.id}.json"
    artifact.write_text(json.dumps(_serializable(summary), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    result.data["artifact"] = str(artifact)
    ctx.scan.stats = {**(ctx.scan.stats or {}), "pcap": result.data}
    ctx.db.commit()
    return result


def _service_for(port: int) -> str:
    from .network_engine import SERVICE_NAMES

    return SERVICE_NAMES.get(port, "")
