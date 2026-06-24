"""
HTTP/3 and QUIC Testing — Check for HTTP/3 support, downgrade attacks,
QUIC configuration, HTTP/3-specific vulnerabilities, and migration issues.
"""

import logging
import re
import socket
import ssl
import struct
from typing import Any

import requests

logger = logging.getLogger("Cascavel.Plugins.HTTP3Test")

# QUIC version constants
QUIC_VERSION_1 = 0x00000001
QUIC_VERSION_DRAFT = 0xFF00001D
QUIC_VERSION_RFC = 0x00000001

# QUIC common ports
QUIC_PORTS = [443, 8443, 4433]

# HTTP/3 ALPN tokens
H3_ALPN = ["h3", "h3-29", "h3-28", "h3-27", "h3-26", "h3-25"]

# Known HTTP/3 security issues
H3_SECURITY_CHECKS: list[dict[str, Any]] = [
    {
        "check": "initial_packet_amplification",
        "severity": "MEDIO",
        "description": "QUIC initial packet amplification attack allows DDoS amplification.",
        "remediation": "Validate initial packet size, implement address validation (retry packets).",
    },
    {
        "check": "connection_migration_abuse",
        "severity": "BAIXO",
        "description": "QUIC connection migration can be abused to bypass IP-based rate limiting.",
        "remediation": "Use token-based rate limiting instead of IP-based. Validate connection migration tokens.",
    },
    {
        "check": "0_rtt_replay",
        "severity": "ALTO",
        "description": "QUIC 0-RTT data is vulnerable to replay attacks.",
        "remediation": "Reject 0-RTT for non-idempotent requests. Implement replay protection with timestamps.",
    },
    {
        "check": "connection_close_amplification",
        "severity": "MEDIO",
        "description": "Connection close flood can exhaust server resources.",
        "remediation": "Rate limit connection close handling, implement connection draining.",
    },
    {
        "check": "stream_multiplexing_dos",
        "severity": "MEDIO",
        "description": "Excessive stream creation can cause resource exhaustion.",
        "remediation": "Enforce maximum concurrent streams per connection. Implement stream-level rate limiting.",
    },
]


def _check_alt_svc_header(
    target: str, session: requests.Session, ports: list[int]
) -> list[dict[str, Any]]:
    """Check for HTTP/3 support via Alt-Svc header."""
    findings: list[dict[str, Any]] = []

    check_urls = []
    if 443 in ports:
        check_urls.append(f"https://{target}")
    if 80 in ports:
        check_urls.append(f"http://{target}")
    if not check_urls:
        check_urls.append(f"https://{target}")

    for url in check_urls:
        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            alt_svc = resp.headers.get("Alt-Svc", "")

            if alt_svc:
                # Parse Alt-Svc for h3 tokens
                h3_found = any(token in alt_svc.lower() for token in ("h3", "h3-29", "h3-28"))

                if h3_found:
                    # Extract port and parameters
                    port_match = re.search(r':(\d+)', alt_svc)
                    alt_port = port_match.group(1) if port_match else "443"

                    # Check for ma (max-age) parameter
                    ma_match = re.search(r'ma=(\d+)', alt_svc)
                    max_age = ma_match.group(1) if ma_match else "not set"

                    findings.append({
                        "tipo": "HTTP3_SUPPORTED",
                        "severidade": "INFO",
                        "titulo": "HTTP/3 support detected via Alt-Svc",
                        "descricao": (
                            f"Alt-Svc header: {alt_svc}. "
                            f"HTTP/3 available on port {alt_port}, max-age: {max_age}."
                        ),
                        "header": "Alt-Svc",
                        "value": alt_svc,
                        "alt_port": alt_port,
                        "max_age": max_age,
                        "remediacao": (
                            "Ensure QUIC/HTTP/3 implementation is up to date. "
                            "Test for HTTP/3-specific vulnerabilities. "
                            "Monitor Alt-Svc header for stale entries."
                        ),
                    })

                    # Check for overly long Alt-Svc max-age
                    if ma_match and int(ma_match.group(1)) > 86400:
                        findings.append({
                            "tipo": "ALT_SVC_LONG_MAX_AGE",
                            "severidade": "BAIXO",
                            "titulo": "Alt-Svc max-age exceeds 24 hours",
                            "descricao": (
                                f"Alt-Svc max-age is {max_age}s ({int(max_age) // 86400} days). "
                                "If HTTP/3 endpoint goes down, clients will keep trying for a long time."
                            ),
                            "max_age": max_age,
                            "remediacao": "Set Alt-Svc max-age to 24-48 hours (86400-172800).",
                        })
                else:
                    findings.append({
                        "tipo": "ALT_SVC_NO_H3",
                        "severidade": "INFO",
                        "titulo": "Alt-Svc present but no HTTP/3",
                        "descricao": f"Alt-Svc header present ({alt_svc}) but does not include h3.",
                        "header": "Alt-Svc",
                        "value": alt_svc,
                        "remediacao": "If HTTP/3 is desired, add h3 token to Alt-Svc header.",
                    })
            else:
                findings.append({
                    "tipo": "NO_ALT_SVC",
                    "severidade": "INFO",
                    "titulo": "No Alt-Svc header (HTTP/3 not advertised)",
                    "descricao": (
                        "Server does not advertise HTTP/3 via Alt-Svc header. "
                        "HTTP/3 may still be available but not advertised."
                    ),
                    "remediacao": (
                        "Add Alt-Svc header to advertise HTTP/3: "
                        "Alt-Svc: h3=\":443\"; ma=86400"
                    ),
                })

            # Also check for HTTP/3 in the response protocol
            if hasattr(resp, 'version') and resp.version:
                version_map = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}
                actual_version = version_map.get(resp.version, f"Unknown ({resp.version})")
                findings.append({
                    "tipo": "HTTP_VERSION",
                    "severidade": "INFO",
                    "titulo": f"Response protocol: {actual_version}",
                    "descricao": f"Server responded using {actual_version}.",
                    "version": actual_version,
                    "remediacao": "N/A",
                })

        except requests.RequestException as e:
            logger.debug(f"Alt-Svc check failed for {url}: {e}")

    return findings


def _check_h3_downgrade(
    target: str, session: requests.Session, ports: list[int]
) -> list[dict[str, Any]]:
    """Test for HTTP/3 downgrade attack vectors."""
    findings: list[dict[str, Any]] = []

    check_url = f"https://{target}" if 443 in ports else f"https://{target}:{ports[0]}" if ports else f"https://{target}"

    try:
        # Check if server allows HTTP/3 downgrade to HTTP/1.1
        # by testing without HTTP/2 and HTTP/3 support
        resp_http1 = session.get(
            check_url,
            headers={
                "Connection": "keep-alive",
                "Upgrade": "",  # Explicitly no upgrade
            },
            timeout=8,
        )

        if resp_http1.status_code == 200:
            # Check security headers that should be present regardless of HTTP version
            security_headers = {
                "Strict-Transport-Security": {
                    "severity": "ALTO",
                    "desc": "HSTS missing. HTTP/3 downgrade to HTTP can be exploited for SSL stripping.",
                },
                "X-Content-Type-Options": {
                    "severity": "MEDIO",
                    "desc": "X-Content-Type-Options missing. MIME sniffing possible in downgrade scenario.",
                },
                "Content-Security-Policy": {
                    "severity": "MEDIO",
                    "desc": "CSP missing. No protection against injection in downgrade responses.",
                },
            }

            for header, info in security_headers.items():
                if header not in resp_http1.headers:
                    findings.append({
                        "tipo": "H3_DOWNGRADE_MISSING_HEADER",
                        "severidade": info["severity"],
                        "titulo": f"Missing {header} (downgrade risk)",
                        "descricao": info["desc"],
                        "header": header,
                        "remediacao": f"Configure {header} header on all HTTP versions.",
                    })

        # Check for protocol negotiation weakness
        # Try to detect if server blindly accepts any protocol
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Test with all ALPN protocols
            context.set_alpn_protocols(H3_ALPN + ["h2", "http/1.1"])
            sock = socket.create_connection((target, 443 if not ports else ports[0]), timeout=5)
            ssock = context.wrap_socket(sock, server_hostname=target)
            selected = ssock.selected_alpn_protocol()

            if selected:
                findings.append({
                    "tipo": "ALPN_NEGOTIATED",
                    "severidade": "INFO",
                    "titulo": f"ALPN negotiated: {selected}",
                    "descricao": (
                        f"Server selected ALPN protocol: {selected}. "
                        f"{'HTTP/3 capable.' if selected.startswith('h3') else 'HTTP/2 or HTTP/1.1 selected.'}"
                    ),
                    "alpn": selected,
                    "remediacao": "Ensure preferred ALPN order is h3, h2, http/1.1 for optimal performance.",
                })
            else:
                findings.append({
                    "tipo": "NO_ALPN",
                    "severidade": "BAIXO",
                    "titulo": "No ALPN protocol negotiated",
                    "descricao": "Server did not negotiate any ALPN protocol. Protocol selection relies on fallback.",
                    "remediacao": "Configure ALPN on the server to enable proper protocol negotiation.",
                })

            ssock.close()
        except Exception as e:
            logger.debug(f"ALPN check failed: {e}")

    except requests.RequestException as e:
        logger.debug(f"Downgrade check failed: {e}")

    return findings


def _check_quic_config(
    target: str, ip: str, ports: list[int]
) -> list[dict[str, Any]]:
    """Check QUIC configuration and UDP port availability."""
    findings: list[dict[str, Any]] = []

    for port in QUIC_PORTS:
        if port not in ports and port != 443:
            continue

        try:
            # QUIC runs over UDP — attempt to detect UDP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            # Send a QUIC Initial packet probe (simplified)
            # QUIC Initial packet format:
            # Header Form (1 bit) + Fixed Bit (1 bit) + Long Packet Type (2 bits)
            # + Reserved Bits (2 bits) + Packet Number Length (2 bits)
            # + Version (4 bytes) + DCID Len (1 byte) + DCID + SCID Len (1 byte) + SCID + ...

            # Build a minimal QUIC Initial probe
            header_byte = 0xC0  # Long header, Initial type
            version = struct.pack(">I", QUIC_VERSION_1)
            dcid = b"\x00" * 8  # 8-byte destination connection ID
            scid = b"\x00" * 8  # 8-byte source connection ID
            token_len = b"\x00"  # No token

            packet = bytes([header_byte]) + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + token_len

            sock.sendto(packet, (ip, port))

            # Try to receive a response (Version Negotiation or Retry)
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    # Check if it's a Version Negotiation packet
                    if len(data) >= 5:
                        first_byte = data[0]
                        if first_byte & 0x80:  # Long header
                            if len(data) >= 9:
                                resp_version = struct.unpack(">I", data[1:5])[0]
                                if resp_version == 0:
                                    # Version Negotiation — server supports QUIC
                                    supported_versions = []
                                    for i in range(9, len(data) - 3, 4):
                                        v = struct.unpack(">I", data[i:i+4])[0]
                                        if v != 0:
                                            supported_versions.append(f"0x{v:08x}")

                                    findings.append({
                                        "tipo": "QUIC_VERSION_NEGOTIATION",
                                        "severidade": "INFO",
                                        "titulo": f"QUIC Version Negotiation on port {port}",
                                        "descricao": (
                                            f"Server sent Version Negotiation packet. "
                                            f"Supported versions: {', '.join(supported_versions[:5]) if supported_versions else 'unknown'}"
                                        ),
                                        "port": port,
                                        "supported_versions": supported_versions[:10],
                                        "remediacao": (
                                            "Ensure server supports QUIC v1 (RFC 9000). "
                                            "Disable draft versions. "
                                            "Implement version aliasing for 0-RTT compatibility."
                                        ),
                                    })
                                else:
                                    # Server responded with a specific version
                                    findings.append({
                                        "tipo": "QUIC_ACTIVE",
                                        "severidade": "INFO",
                                        "titulo": f"QUIC active on port {port}",
                                        "descricao": f"QUIC server responded with version 0x{resp_version:08x}.",
                                        "port": port,
                                        "version": f"0x{resp_version:08x}",
                                        "remediacao": "Ensure QUIC implementation is up to date. Monitor for QUIC-specific CVEs.",
                                    })
            except socket.timeout:
                # No response — QUIC may not be available, or firewall blocks UDP
                findings.append({
                    "tipo": "QUIC_NO_RESPONSE",
                    "severidade": "INFO",
                    "titulo": f"No QUIC response on port {port} (UDP)",
                    "descricao": (
                        f"QUIC probe to {ip}:{port}/UDP received no response. "
                        "QUIC may be disabled or UDP traffic is filtered."
                    ),
                    "port": port,
                    "remediacao": "If HTTP/3 is desired, ensure UDP port 443 is open and QUIC is enabled.",
                })

            sock.close()
        except Exception as e:
            logger.debug(f"QUIC config check failed on port {port}: {e}")

    return findings


def _check_h3_vulnerabilities(
    target: str, session: requests.Session, ports: list[int]
) -> list[dict[str, Any]]:
    """Check for HTTP/3-specific vulnerabilities."""
    findings: list[dict[str, Any]] = []

    check_url = f"https://{target}" if 443 in ports else f"https://{target}:{ports[0]}" if ports else f"https://{target}"

    try:
        # Test for 0-RTT support (replay vulnerability)
        # We check if the server accepts early data by looking at timing
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["h2", "http/1.1"])

            sock = socket.create_connection((target, 443 if not ports else ports[0]), timeout=5)
            ssock = context.wrap_socket(sock, server_hostname=target)

            # Check TLS session ticket (indicates 0-RTT capability)
            session_ticket = ssock.session and ssock.session.has_ticket
            if session_ticket:
                findings.append({
                    "tipo": "TLS_SESSION_TICKET",
                    "severidade": "MEDIO",
                    "titulo": "TLS session tickets enabled (0-RTT risk)",
                    "descricao": (
                        "Server supports TLS session tickets, which enables 0-RTT resumption. "
                        "0-RTT data is vulnerable to replay attacks."
                    ),
                    "remediacao": (
                        "Implement anti-replay protection for 0-RTT. "
                        "Reject 0-RTT for non-idempotent requests. "
                        "Use single-use session tickets."
                    ),
                })

            # Check TLS version
            tls_version = ssock.version()
            if tls_version and "TLSv1.3" in tls_version:
                findings.append({
                    "tipo": "TLS_13",
                    "severidade": "INFO",
                    "titulo": "TLS 1.3 enabled (supports QUIC)",
                    "descricao": f"Server uses {tls_version}, which is required for QUIC/HTTP/3.",
                    "tls_version": tls_version,
                    "remediacao": "TLS 1.3 is recommended. Ensure cipher suite configuration is secure.",
                })
            elif tls_version:
                findings.append({
                    "tipo": "TLS_OLD",
                    "severidade": "ALTO",
                    "titulo": f"Server uses {tls_version} (QUIC requires TLS 1.3)",
                    "descricao": (
                        f"Server negotiates {tls_version}. QUIC/HTTP/3 requires TLS 1.3. "
                        "Older TLS versions have known vulnerabilities."
                    ),
                    "tls_version": tls_version,
                    "remediacao": "Upgrade to TLS 1.3. Disable TLS 1.0, 1.1, and potentially 1.2.",
                })

            ssock.close()
        except Exception as e:
            logger.debug(f"TLS check failed: {e}")

        # Check for common HTTP/3 implementation issues via HTTP/2
        resp = session.get(check_url, timeout=8)

        # Check for missing security headers (applicable to all HTTP versions)
        critical_headers = {
            "Strict-Transport-Security": {
                "severity": "ALTO",
                "desc": "HSTS missing. Required for HTTP/3 adoption to prevent downgrade attacks.",
            },
            "X-Frame-Options": {
                "severity": "MEDIO",
                "desc": "X-Frame-Options missing. Clickjacking possible across HTTP versions.",
            },
        }

        for header, info in critical_headers.items():
            if header not in resp.headers:
                findings.append({
                    "tipo": "MISSING_HEADER",
                    "severidade": info["severity"],
                    "titulo": f"Missing {header}",
                    "descricao": info["desc"],
                    "header": header,
                    "remediacao": f"Configure {header} on all endpoints.",
                })

    except requests.RequestException as e:
        logger.debug(f"H3 vulnerability check failed: {e}")

    return findings


def _check_h2_h3_migration(
    target: str, session: requests.Session, ports: list[int]
) -> list[dict[str, Any]]:
    """Check for HTTP/2 to HTTP/3 migration issues."""
    findings: list[dict[str, Any]] = []

    check_url = f"https://{target}" if 443 in ports else f"https://{target}:{ports[0]}" if ports else f"https://{target}"

    try:
        # Check HTTP/2 support
        resp = session.get(check_url, timeout=8)

        # Look for HTTP/2 specific headers that may not work in HTTP/3
        h2_specific_headers = [
            "HTTP2-Settings",
            "X-HTTP2-Stream-ID",
        ]

        for header in h2_specific_headers:
            if header in resp.headers:
                findings.append({
                    "tipo": "H2_SPECIFIC_HEADER",
                    "severidade": "BAIXO",
                    "titulo": f"HTTP/2-specific header present: {header}",
                    "descricao": (
                        f"Header {header} is HTTP/2-specific and will not work in HTTP/3. "
                        "Migration to HTTP/3 may break functionality relying on this header."
                    ),
                    "header": header,
                    "remediacao": f"Remove dependency on {header}. Use version-agnostic alternatives.",
                })

        # Check for Server Push (deprecated in HTTP/3)
        if "Link" in resp.headers:
            link_header = resp.headers["Link"]
            if "preload" in link_header.lower():
                findings.append({
                    "tipo": "SERVER_PUSH",
                    "severidade": "BAIXO",
                    "titulo": "Server Push preload hint detected",
                    "descricao": (
                        "Link: rel=preload header detected. HTTP/2 Server Push is deprecated in HTTP/3. "
                        "Use 103 Early Hints instead."
                    ),
                    "header": "Link",
                    "value": link_header[:200],
                    "remediacao": "Migrate from Server Push to 103 Early Hints for HTTP/3 compatibility.",
                })

        # Check for HTTP/2 connection-specific headers (forbidden in HTTP/3)
        connection_specific = ["Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade"]
        for header in connection_specific:
            value = resp.headers.get(header)
            if value:
                findings.append({
                    "tipo": "CONNECTION_HEADER",
                    "severidade": "BAIXO",
                    "titulo": f"Connection-specific header: {header}",
                    "descricao": (
                        f"Header {header}: {value} is connection-specific. "
                        "HTTP/3 uses different connection management. "
                        "This header will be ignored or cause issues in HTTP/3."
                    ),
                    "header": header,
                    "value": value,
                    "remediacao": (
                        "Remove connection-specific headers from application code. "
                        "Let the server/proxy handle connection management."
                    ),
                })

        # Check for HSTS readiness (required for smooth HTTP/3 migration)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    findings.append({
                        "tipo": "HSTS_SHORT_MAX_AGE",
                        "severidade": "MEDIO",
                        "titulo": f"HSTS max-age too short ({max_age}s)",
                        "descricao": (
                            f"HSTS max-age is {max_age}s ({max_age // 86400} days). "
                            "For HTTP/3 migration, HSTS should have max-age >= 1 year "
                            "to ensure clients always use HTTPS (required for QUIC)."
                        ),
                        "max_age": max_age,
                        "remediacao": "Set HSTS max-age to at least 31536000 (1 year). Add to HSTS preload list.",
                    })

            if "includeSubDomains" not in hsts:
                findings.append({
                    "tipo": "HSTS_NO_SUBDOMAINS",
                    "severidade": "BAIXO",
                    "titulo": "HSTS missing includeSubDomains",
                    "descricao": "HSTS does not include subdomains. Subdomains may be accessed over HTTP during migration.",
                    "remediacao": "Add includeSubDomains to HSTS header for complete HTTP/3 migration.",
                })
        else:
            findings.append({
                "tipo": "NO_HSTS",
                "severidade": "ALTO",
                "titulo": "HSTS not configured (HTTP/3 migration blocker)",
                "descricao": (
                    "HSTS is required for HTTP/3 adoption. Without HSTS, clients may "
                    "not use HTTPS consistently, preventing QUIC connections."
                ),
                "remediacao": (
                    "Enable HSTS with max-age >= 31536000 and includeSubDomains. "
                    "Submit to HSTS preload list after testing."
                ),
            })

    except requests.RequestException as e:
        logger.debug(f"H2/H3 migration check failed: {e}")

    return findings


def run(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[str, str],
    context: dict | None = None,
) -> dict[str, Any] | None:
    """Main plugin entry point — HTTP/3 and QUIC testing."""
    resultados: list[dict[str, Any]] = []

    session = requests.Session()
    session.headers.update({
        "Accept": "text/html, application/json, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })

    try:
        # 1. Alt-Svc header check (HTTP/3 support detection)
        resultados.extend(_check_alt_svc_header(target, session, ports))

        # 2. HTTP/3 downgrade attack checks
        resultados.extend(_check_h3_downgrade(target, session, ports))

        # 3. QUIC configuration check
        resultados.extend(_check_quic_config(target, ip, ports))

        # 4. HTTP/3-specific vulnerabilities
        resultados.extend(_check_h3_vulnerabilities(target, session, ports))

        # 5. HTTP/2 to HTTP/3 migration issues
        resultados.extend(_check_h2_h3_migration(target, session, ports))

        if not resultados:
            return None

        severities = [r["severidade"] for r in resultados]
        crit = severities.count("CRITICO")
        alto = severities.count("ALTO")

        resultados.insert(0, {
            "tipo": "RESUMO",
            "severidade": "CRITICO" if crit > 0 else ("ALTO" if alto > 0 else "MEDIO"),
            "titulo": f"HTTP/3 & QUIC Test — {len(resultados) - 1} findings",
            "descricao": (
                f"HTTP/3 and QUIC analysis of {target} found "
                f"{crit} critical, {alto} high, "
                f"{severities.count('MEDIO')} medium, "
                f"{severities.count('BAIXO')} low, "
                f"{severities.count('INFO')} info findings."
            ),
            "total_resultados": len(resultados) - 1,
            "remediacao": (
                "Enable HTTP/3 with TLS 1.3, configure Alt-Svc header with 24h max-age, "
                "implement 0-RTT replay protection, enable HSTS with includeSubDomains, "
                "migrate from Server Push to 103 Early Hints."
            ),
        })

        return {"plugin": "http3_test", "resultados": resultados}

    except Exception as e:
        logger.error(f"HTTP/3 test failed for {target}: {e}")
        return {
            "plugin": "http3_test",
            "resultados": [{
                "tipo": "ERRO",
                "severidade": "INFO",
                "titulo": "Test error",
                "descricao": f"HTTP/3 test failed: {e}",
                "remediacao": "N/A",
            }],
        }
