"""Network engine — real TCP scanning, service fingerprinting and (optionally) Nmap.

Two interchangeable implementations:
* built-in asyncio TCP connect scanner (always available, no root/admin rights),
* Nmap adapter when nmap is installed (XML output parsed with defusedxml).

User input never reaches a command line: only validated IPs and a port list built
from a strict numeric grammar are passed to nmap.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import subprocess
from typing import Any

from defusedxml import ElementTree

from ..core.netguard import authorize_target
from ..services.assets import record_change, recompute_asset_risk, upsert_asset, upsert_service
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult

log = logging.getLogger("nexus.engine.network")

MAX_PORTS = 2000
MAX_CIDR_HOSTS = 256
CONNECT_CONCURRENCY = 250
DEFAULT_TIMEOUT = 1.2

SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    4443: "https-alt", 5000: "http-alt", 5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8161: "activemq", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9042: "cassandra", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 10000: "webmin", 10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 50000: "sap", 61616: "activemq",
}

COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 873, 993, 995, 1080, 1433,
    1521, 1883, 2049, 2181, 2375, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443,
    7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 10000, 10250,
    11211, 15672, 27017, 27018, 50000, 61616,
)

# port -> (severity, title, description, impact, remediation-tail)
RISK_CATALOG: dict[int, tuple[str, str, str, str]] = {
    23: ("high", "Telnet exposed", "Telnet transmits credentials and sessions in clear text.", "Any client on the path can capture the administrator credentials."),
    21: ("medium", "FTP exposed", "FTP authentication and data are not encrypted.", "Credentials and transferred files can be intercepted."),
    445: ("high", "SMB exposed", "File-sharing service reachable from the network.", "Central vector for ransomware propagation and credential theft."),
    139: ("high", "NetBIOS session service exposed", "Legacy SMB over NetBIOS is reachable.", "Enables enumeration and lateral movement on Windows networks."),
    3389: ("high", "RDP exposed to the network", "Remote Desktop is directly reachable.", "Brute-force and pre-auth RCE (BlueKeep-class) exposure; often the entry point of ransomware crews."),
    5900: ("high", "VNC exposed", "Remote screen access reachable; often weak or absent authentication.", "Full interactive control of the desktop."),
    3306: ("high", "MySQL exposed", "Database port reachable from outside its application tier.", "Direct database attack surface: credential brute force, data exfiltration, and (with FILE privilege) server-side file read."),
    5432: ("high", "PostgreSQL exposed", "Database port reachable from outside its application tier.", "Direct database attack surface and privilege-escalation paths."),
    27017: ("high", "MongoDB exposed", "MongoDB is reachable on the network.", "Historically shipped without authentication — automated bots ransom exposed instances."),
    6379: ("critical", "Redis exposed", "Redis is reachable on the network.", "When unauthenticated, Redis allows arbitrary key access and, via RDB writes, remote code execution."),
    9200: ("high", "Elasticsearch exposed", "Elasticsearch HTTP API is reachable.", "Unprotected indices leak the entire dataset and the API is not designed for direct internet exposure."),
    9300: ("high", "Elasticsearch transport port exposed", "Cluster transport port is reachable.", "Allows cluster manipulation and data access without the HTTP layer's controls."),
    11211: ("high", "Memcached exposed", "Memcached is reachable.", "Data disclosure and reflection/amplification DDoS abuse."),
    2375: ("critical", "Docker API exposed without TLS", "The Docker daemon socket is reachable over TCP.", "Unauthenticated Docker API equals root on the host: containers can be created with host mounts."),
    2376: ("high", "Docker API exposed", "Docker daemon API reachable (TLS variant).", "Compromise of the daemon yields host-level control."),
    6443: ("medium", "Kubernetes API server exposed", "Cluster API is directly reachable.", "Expands the attack surface of the control plane."),
    10250: ("high", "Kubelet API exposed", "Kubelet endpoint reachable.", "Kubelet endpoints have historically allowed command execution in pods."),
    7001: ("high", "WebLogic exposed", "Oracle WebLogic console/port reachable.", "WebLogic has a long record of unauthenticated RCE (deserialization) issues."),
    8161: ("high", "ActiveMQ web console exposed", "ActiveMQ console reachable.", "Historically vulnerable to unauthenticated RCE (CVE-2016-3088 filenames)."),
    15672: ("medium", "RabbitMQ management UI exposed", "RabbitMQ management interface reachable.", "Management credentials are frequently left at defaults and permit queue/broker manipulation."),
    10000: ("high", "Webmin exposed", "Webmin administrative interface reachable.", "Webmin has had critical unauthenticated RCE vulnerabilities."),
    161: ("medium", "SNMP exposed", "SNMP is reachable.", "Default community strings (public/private) expose device configuration and statistics."),
    389: ("medium", "LDAP reachable", "Directory service port is reachable.", "Enables anonymous or authenticated directory enumeration."),
    873: ("medium", "rsync exposed", "rsync daemon reachable.", "Misconfigured rsync modules allow anonymous file read or write."),
    2049: ("medium", "NFS exposed", "NFS is reachable.", "Misconfigured exports expose filesystems to anyone who can reach the port."),
}


def parse_ports(spec: str | None, default: tuple[int, ...] = COMMON_PORTS) -> list[int]:
    """Strict port grammar: '22,80,443,8000-8100'. Never trusts arbitrary text."""
    if not spec or not str(spec).strip():
        return list(default)
    text = str(spec).strip()
    if not re.fullmatch(r"[0-9,\-\s]+", text):
        raise ValueError("invalid port specification — only digits, commas and ranges are allowed")
    ports: list[int] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            if not (start_text.isdigit() and end_text.isdigit()):
                raise ValueError(f"invalid port range: {chunk}")
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            if end - start > 5000:
                raise ValueError("port range too large (max 5000 ports per range)")
            ports.extend(range(max(1, start), min(65535, end) + 1))
        else:
            if not chunk.isdigit():
                raise ValueError(f"invalid port: {chunk}")
            ports.append(int(chunk))
    ports = sorted({p for p in ports if 1 <= p <= 65535})
    if len(ports) > MAX_PORTS:
        raise ValueError(f"too many ports requested ({len(ports)} > {MAX_PORTS})")
    return ports


def expand_targets(target: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand a CIDR target into individual hosts (bounded)."""
    if target.get("type") != "cidr" and "/" not in str(target.get("value", "")):
        return [target]
    try:
        network = ipaddress.ip_network(str(target.get("value")).strip(), strict=False)
    except ValueError:
        return [target]
    hosts = list(network.hosts())[:MAX_CIDR_HOSTS]
    return [{**target, "type": "ip", "value": str(ip), "host": str(ip)} for ip in hosts]


# ---------------------------------------------------------------------------
# Built-in scanner
# ---------------------------------------------------------------------------
async def _tcp_check(host: str, port: int, timeout: float) -> tuple[int, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, "open"
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, "closed"


async def scan_ports(host: str, ports: list[int], timeout: float = DEFAULT_TIMEOUT) -> dict[int, str]:
    semaphore = asyncio.Semaphore(CONNECT_CONCURRENCY)
    results: dict[int, str] = {}

    async def worker(port: int) -> None:
        async with semaphore:
            port_number, state = await _tcp_check(host, port, timeout)
            if state == "open":
                results[port_number] = state

    await asyncio.gather(*(worker(p) for p in ports), return_exceptions=True)
    return results


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Read a service banner (or provoke one) — read-only, single connection."""
    try:
        if port in (443, 8443, 4443, 9443):
            from .tls_engine import inspect_tls

            report = await asyncio.to_thread(inspect_tls, host, port, timeout)
            cert = report.get("cert") or {}
            if report.get("connected"):
                return f"TLS {report.get('protocol')} cipher={report.get('cipher')} cn={cert.get('common_name', '')}"
            return ""

        if port in (80, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 3000, 5000, 9200, 5601, 15672, 10000, 8161, 2375, 5984, 9418):
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            request = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NexusCyberDefense/0.1\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            writer.close()
            return data.decode("utf-8", errors="replace")

        if port == 6379:  # Redis: read-only PING
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            return data.decode("utf-8", errors="replace")

        # Passive banner read for SSH/SMTP/FTP/MySQL/MongoDB-style greetings
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def fingerprint_banner(port: int, banner: str) -> tuple[str, str, str]:
    """Return (service name, product, version) — heuristic but evidence-backed."""
    text = banner or ""
    lowered = text.lower()
    product, version = "", ""

    patterns = (
        (r"SSH-([\d.]+)-([^\s]+)", "ssh", "OpenSSH/ssh"),
        (r"^220[- ].*?(Microsoft ESMTP|Postfix|Exim|Sendmail|Exchange)", "smtp", ""),
        (r"^220[- ].*(vsftpd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP)", "ftp", ""),
        (r"^\+OK.*?(Dovecot|Courier)", "pop3", ""),
        (r"\* OK.*?(Dovecot|Courier)", "imap", ""),
        (r"mysql_native_password|MariaDB|MySQL", "mysql", ""),
        (r"server:\s*([^\r\n]+)", "http", ""),
    )
    for pattern, service, _product_hint in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            product = (match.group(1) if match.groups() else "").strip()[:80]
            break

    version_match = re.search(r"([A-Za-z][A-Za-z0-9\-_]*)[/ ]v?(\d+(?:\.\d+){1,3})", text)
    if version_match:
        product = product or version_match.group(1)
        version = version_match.group(2)

    name = SERVICE_NAMES.get(port, "unknown")
    if "HTTP/" in text.upper() or lowered.startswith("http/"):
        name = "https" if port in (443, 8443, 4443) else "http"
    return name, product[:120], version[:40]


# ---------------------------------------------------------------------------
# Nmap adapter (optional)
# ---------------------------------------------------------------------------
def nmap_available() -> str | None:
    from .registry import find_nmap

    return find_nmap()


def run_nmap_scan(host: str, ports: list[int], timeout: int = 300) -> dict[str, Any]:
    """Run nmap with a fixed, audited argument set. No user text ever reaches the command line."""
    nmap_path = nmap_available()
    if not nmap_path:
        return {"available": False, "error": "nmap_not_found"}
    if not re.fullmatch(r"[0-9a-fA-F:.]{3,45}", host):
        return {"available": True, "error": "invalid_host"}
    port_spec = ",".join(str(p) for p in ports[:MAX_PORTS])
    command = [
        nmap_path,
        "-Pn",           # no ICMP echo dependency
        "-sT",           # connect scan: no raw sockets, no admin rights needed
        "-T3",           # polite timing
        "--max-retries", "2",
        "--host-timeout", f"{max(timeout // 2, 60)}s",
        "-sV",           # service/version detection
        "--version-light",
        "-p", port_spec,
        "-oX", "-",
        host,
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, validated inputs, no shell
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "nmap_timeout"}
    except Exception as exc:
        return {"available": True, "error": f"nmap_failed: {exc}"}

    if completed.returncode != 0 and not completed.stdout:
        return {"available": True, "error": f"nmap_exit_{completed.returncode}", "stderr": completed.stderr[:500].decode(errors="replace")}

    services: list[dict[str, Any]] = []
    try:
        root = ElementTree.fromstring(completed.stdout)
        for port_element in root.iter("port"):
            state_element = port_element.find("state")
            if state_element is None or state_element.get("state") != "open":
                continue
            service_element = port_element.find("service")
            services.append(
                {
                    "port": int(port_element.get("portid", "0")),
                    "protocol": port_element.get("protocol", "tcp"),
                    "name": (service_element.get("name") if service_element is not None else "") or "",
                    "product": (service_element.get("product") if service_element is not None else "") or "",
                    "version": (service_element.get("version") if service_element is not None else "") or "",
                    "extra_info": (service_element.get("extrainfo") if service_element is not None else "") or "",
                }
            )
    except Exception as exc:
        return {"available": True, "error": f"nmap_parse_failed: {exc}"}
    return {"available": True, "services": services, "command_version": "nmap"}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def evaluate(ctx: EngineContext, host: str, services: list[dict[str, Any]], asset_id: str) -> int:
    created = 0
    for service in services:
        port = int(service["port"])
        catalog = RISK_CATALOG.get(port)
        if catalog:
            severity, title, description, impact = catalog
            ctx.save(
                check_id=f"network_service_{port}",
                category="network_service",
                title=f"{title} on {host}:{port}",
                severity=severity,
                confidence="certain",
                target=host,
                location=f"{host}:{port}/tcp",
                description=f"{description} (banner: {(service.get('banner') or service.get('name') or '')[:120]})",
                impact=impact,
                remediation=f"Restrict port {port} with firewall rules or a private network/VPN, require authentication, and keep the service patched; if it must be public, put it behind an authenticating proxy.",
                references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://attack.mitre.org/techniques/T1046/"],
                cwe="CWE-284",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset_id,
                service_id=service.get("service_id"),
                verified=True,
                evidence={
                    "kind": "port_banner",
                    "label": f"TCP {host}:{port}",
                    "response": (service.get("banner") or "")[:1200],
                    "source": ENGINE_NAME,
                },
                tags=["network", "exposure"],
            )
            created += 1

        if port == 6379 and "+PONG" in (service.get("banner") or "").upper():
            ctx.save(
                check_id="redis_unauthenticated",
                category="network_service",
                title=f"Redis on {host}:6379 answered PING without authentication",
                severity="critical",
                confidence="certain",
                target=host,
                location=f"{host}:6379/tcp",
                description="The Redis instance replied +PONG to an unauthenticated PING command.",
                impact="Anyone who can reach this port can read, modify and delete all data, and in many configurations write files to the server (cron/SSH keys) to obtain command execution.",
                remediation="Bind Redis to a private interface, enable requirepass with a long random password, disable dangerous commands (CONFIG, DEBUG, MODULE) and never expose it to the internet.",
                references=["https://redis.io/docs/management/security/", "https://www.cisa.gov/news-events/alerts"],
                cwe="CWE-306",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset_id,
                verified=True,
                active_check=True,
                evidence={
                    "kind": "port_banner",
                    "label": "Unauthenticated PING",
                    "request": "PING\\r\\n",
                    "response": (service.get("banner") or "")[:200],
                    "source": ENGINE_NAME,
                },
                tags=["network", "redis", "critical"],
            )
            created += 1

        if port in (80, 8080, 8000, 8888) and service.get("state") == "open":
            banner = (service.get("banner") or "").lstrip()
            if banner.upper().startswith("HTTP/"):
                ctx.save(
                    check_id=f"cleartext_http_{port}",
                    category="network_service",
                    title=f"Unencrypted HTTP service on {host}:{port}",
                    severity="low",
                    confidence="certain",
                    target=host,
                    location=f"{host}:{port}/tcp",
                    description="The service speaks plain HTTP.",
                    impact="Traffic (including any credentials submitted) can be read or modified in transit.",
                    remediation="Serve HTTPS only, redirect HTTP to HTTPS and enable HSTS.",
                    references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                    cwe="CWE-319",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=asset_id,
                    tags=["network", "tls"],
                )
                created += 1
    return created


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={"hosts": []})
    options = ctx.scan.options or {}
    ports = parse_ports(options.get("ports"))
    timeout = float(options.get("connect_timeout", DEFAULT_TIMEOUT))
    use_nmap = bool(options.get("use_nmap")) and nmap_available() is not None

    for raw_target in targets:
        for target in expand_targets(raw_target):
            ctx.check_cancel()
            host = str(target.get("host") or target.get("value") or "").strip()
            if not host:
                continue
            # A TCP port scan is an active probe: it always needs an active-authorized
            # scope entry, regardless of the nominal scan profile.
            decision = authorize_target(ctx.db, ctx.project.id, host, require_active=True)
            if not decision.allowed:
                ctx.emit(f"Host skipped — {decision.reason}: {decision.detail}", level="warn", phase="scope_check")
                continue

            asset, created = upsert_asset(
                ctx.db,
                project_id=ctx.project.id,
                asset_type="ip" if _is_ip(host) else "host",
                value=host,
                scope_id=decision.scope_id,
                source="scan",
                scan_id=ctx.scan.id,
            )
            if created:
                result.assets += 1
            ctx.db.commit()

            ctx.phase("ports", "running", progress=10)
            ctx.emit(
                f"Scanning {len(ports)} port(s) on {host} using {'nmap' if use_nmap else 'the built-in TCP connect scanner'} …",
                phase="ports",
                kind="metric",
                data={"ports": len(ports), "engine": "nmap" if use_nmap else "builtin-tcp"},
            )
            host_services: list[dict[str, Any]] = []

            if use_nmap:
                nmap_result = await asyncio.to_thread(run_nmap_scan, host, ports, int(options.get("nmap_timeout", 420)))
                if nmap_result.get("error"):
                    ctx.emit(f"nmap failed ({nmap_result['error']}) — falling back to the built-in scanner.", level="warn", phase="ports")
                    use_nmap_here = False
                else:
                    use_nmap_here = True
                    for item in nmap_result.get("services", []):
                        host_services.append({**item, "banner": f"{item.get('product','')} {item.get('version','')}".strip()})
            else:
                use_nmap_here = False

            if not use_nmap_here:
                open_ports = await scan_ports(host, ports, timeout)
                ctx.emit(f"{len(open_ports)} open port(s) found on {host}.", phase="ports", data={"open": sorted(open_ports)})
                ctx.phase("ports", "done", progress=100)
                ctx.phase("fingerprint", "running", progress=20)
                for port in sorted(open_ports):
                    ctx.check_cancel()
                    banner = await grab_banner(host, port)
                    name, product, version = fingerprint_banner(port, banner)
                    host_services.append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "name": name,
                            "product": product,
                            "version": version,
                            "banner": banner[:1200],
                        }
                    )
            else:
                ctx.phase("ports", "done", progress=100)
                ctx.phase("fingerprint", "done", progress=100)

            # Persist services + change detection
            for service in host_services:
                service_row, service_created, changed = upsert_service(
                    ctx.db,
                    project_id=ctx.project.id,
                    asset=asset,
                    port=int(service["port"]),
                    protocol=service.get("protocol", "tcp"),
                    state="open",
                    name=service.get("name", ""),
                    product=service.get("product", ""),
                    version=service.get("version", ""),
                    banner=service.get("banner", ""),
                    source="nmap" if use_nmap_here else "nexus-tcp",
                )
                service["service_id"] = service_row.id
                if service_created:
                    result.services += 1
                    if asset.last_scanned_at is not None:
                        record_change(
                            ctx.db,
                            project_id=ctx.project.id,
                            asset_id=asset.id,
                            service_id=service_row.id,
                            scan_id=ctx.scan.id,
                            kind="new_service",
                            severity="medium",
                            summary=f"New service on {host}:{service['port']}" + (f" ({service.get('product','')} {service.get('version','')})".strip()),
                            after={"port": service["port"], "name": service.get("name")},
                        )
                elif changed:
                    record_change(
                        ctx.db,
                        project_id=ctx.project.id,
                        asset_id=asset.id,
                        service_id=service_row.id,
                        scan_id=ctx.scan.id,
                        kind="service_changed",
                        severity="low",
                        summary=f"{host}:{service['port']} changed: {', '.join(changed)}",
                        before={field: "previous" for field in changed},
                        after={field: service.get(field) for field in changed},
                    )
            ctx.db.commit()

            created_findings = evaluate(ctx, host, host_services, asset.id)
            result.findings += created_findings
            asset.last_scanned_at = _now()
            recompute_asset_risk(ctx.db, asset)
            ctx.db.commit()

            result.data["hosts"].append(
                {
                    "host": host,
                    "open_ports": len(host_services),
                    "services": [
                        {"port": s["port"], "name": s.get("name"), "product": s.get("product"), "version": s.get("version")}
                        for s in host_services[:40]
                    ],
                    "engine": "nmap" if use_nmap_here else "builtin-tcp",
                }
            )
            ctx.phase("store", "done", progress=100)

    ctx.scan.stats = {**(ctx.scan.stats or {}), "network": result.data}
    ctx.db.commit()
    return result


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _now():
    from ..core.utils import utcnow

    return utcnow()
