"""
Firmware Analysis — Check for exposed firmware endpoints, version disclosure,
update mechanism vulnerabilities, hardcoded credentials, and debug interfaces.
"""

import logging
import re
from typing import Any

import requests

logger = logging.getLogger("Cascavel.Plugins.FirmwareAnalysis")

# Firmware download / update endpoints
FIRMWARE_PATHS: list[str] = [
    "/firmware",
    "/firmware/download",
    "/firmware/update",
    "/firmware/upgrade",
    "/firmware/latest",
    "/firmware/check",
    "/firmware/version",
    "/firmware/info",
    "/firmware/status",
    "/fw/update",
    "/fw/download",
    "/fw/latest",
    "/ota/update",
    "/ota/download",
    "/ota/check",
    "/ota/version",
    "/update",
    "/update/check",
    "/update/download",
    "/upgrade",
    "/upgrade/check",
    "/system/update",
    "/system/firmware",
    "/device/update",
    "/device/firmware",
    "/admin/firmware",
    "/admin/update",
    "/cgi-bin/firmware",
    "/cgi-bin/update",
    "/cgi-bin/upgrade",
    "/api/firmware",
    "/api/update",
    "/api/ota",
    "/api/v1/firmware",
    "/api/v1/ota",
    "/recovery",
    "/recovery/firmware",
    "/bootloader",
    "/boot/firmware",
    "/flash",
    "/flash/update",
    "/upload/firmware",
    "/downloads/firmware",
    "/support/firmware",
    "/resources/firmware",
    "/static/firmware",
    "/pub/firmware",
    "/release/firmware",
]

# Debug / hardware interface paths
DEBUG_INTERFACE_PATHS: list[str] = [
    "/debug",
    "/debug/console",
    "/debug/serial",
    "/debug/uart",
    "/debug/jtag",
    "/debug/swd",
    "/debug/flash",
    "/debug/memory",
    "/debug/registers",
    "/shell",
    "/cli",
    "/console",
    "/serial",
    "/terminal",
    "/admin/console",
    "/admin/shell",
    "/admin/terminal",
    "/diagnostics",
    "/diag",
    "/diag/serial",
    "/diag/interface",
    "/hardware",
    "/hardware/debug",
    "/hardware/info",
    "/hardware/diag",
    "/hw/debug",
    "/hw/console",
    "/tftp",
    "/tftpboot",
    "/pxe",
    "/netboot",
    "/uboot",
    "/u-boot",
    "/bootenv",
    "/proc",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/filesystems",
    "/proc/mounts",
    "/sys",
    "/sys/class",
    "/sys/firmware",
    "/sys/firmware/devicetree",
    "/sys/hardware",
    "/dev",
    "/dev/mem",
    "/dev/kmem",
    "/dev/console",
]

# Version disclosure patterns
VERSION_PATTERNS: list[str] = [
    r"[Ff]irmware[:\s]+v?[\d]+\.[\d]+[\.\d]*",
    r"[Ff]w[_-]?[Vv]ersion[:\s]+[\d]+\.[\d]+",
    r"[Ss]oftware[_-]?[Vv]ersion[:\s]+[\d]+\.[\d]+",
    r"[Hh]ardware[_-]?[Vv]ersion[:\s]+[\d]+\.[\d]+",
    r"[Bb]ootloader[:\s]+v?[\d]+\.[\d]+",
    r"[Bb]uild[:\s]+[\d]+",
    r"[Rr]evision[:\s]+[\w\d]+",
    r"[Mm]odel[:\s]+[\w\-]+",
    r"[Bb]oard[:\s]+[\w\-]+",
    r"[Pp]latform[:\s]+[\w\-]+",
    r"[Ss]oc[:\s]+[\w\-]+",
    r"[Cc]hipset[:\s]+[\w\-]+",
    r"[Kk]ernel[:\s]+[\d]+\.[\d]+",
    r"[Uu]-?[Bb]oot[:\s]+[\d]+\.[\d]+",
    r"[Oo]pen[Ww]rt[\s]+[\d]+\.[\d]+",
    r"[Dd]ebian[\s]+[\d]+",
    r"[Bb]uildroot[\s]+[\d]+",
    r"[Yy]octo[\s]+[\d]+\.[\d]+",
]

# Hardcoded credential patterns in firmware endpoints
CREDENTIAL_PATTERNS: list[str] = [
    r"password\s*[:=]\s*[\"']?[^\s\"']{4,}",
    r"passwd\s*[:=]\s*[\"']?[^\s\"']{4,}",
    r"secret\s*[:=]\s*[\"']?[^\s\"']{8,}",
    r"api[_-]?key\s*[:=]\s*[\"']?[^\s\"']{8,}",
    r"token\s*[:=]\s*[\"']?[^\s\"']{8,}",
    r"auth[_-]?key\s*[:=]\s*[\"']?[^\s\"']{8,}",
    r"private[_-]?key",
    r"BEGIN\s+(RSA\s+)?PRIVATE\s+KEY",
    r"default[_-]?pass",
    r"admin[_-]?pass",
    r"root[_-]?pass",
    r"ftp[_-]?pass",
    r"ssh[_-]?pass",
    r"telnet[_-]?pass",
    r"credentials?\s*[:=]",
    r"login\s*[:=]\s*[\"']?\w{3,}",
    r"username\s*[:=]\s*[\"']?\w{3,}",
    r"mqtt[_-]?pass",
    r"wifi[_-]?pass",
    r"wpa[_-]?pass",
]

# Insecure firmware update indicators
INSECURE_UPDATE_INDICATORS: list[str] = [
    "http://",  # HTTP instead of HTTPS for firmware download
    "ftp://",  # FTP for firmware transfer
    "tftp://",  # TFTP (unencrypted)
    "no-verify",
    "skip-verify",
    "insecure",
    "no-checksum",
    "no-signature",
    "unsigned",
    "allow-unsigned",
    "bypass-verify",
    "force-update",
    "no-rollback",
]


def _check_firmware_endpoints(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Probe for exposed firmware download and update endpoints."""
    findings: list[dict[str, Any]] = []

    for path in FIRMWARE_PATHS:
        try:
            url = f"{base_url}{path}"
            resp = session.get(url, timeout=8, allow_redirects=False)

            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                body_preview = resp.text[:1000]

                # Check if it's a binary firmware download
                is_binary = any(ct in content_type.lower() for ct in (
                    "application/octet-stream", "application/zip", "application/gzip",
                    "application/x-tar", "application/x-compressed", "binary",
                ))

                severity = "ALTO" if is_binary else "MEDIO"
                if is_binary:
                    severity = "CRITICO"

                findings.append({
                    "tipo": "FIRMWARE_ENDPOINT",
                    "severidade": severity,
                    "titulo": f"Firmware endpoint exposed: {path}",
                    "descricao": (
                        f"Firmware endpoint {path} returned HTTP {resp.status_code}. "
                        f"Content-Type: {content_type}. "
                        f"{'Binary firmware download available.' if is_binary else 'Informational endpoint.'}"
                    ),
                    "endpoint": url,
                    "content_type": content_type,
                    "content_length": len(resp.content),
                    "is_binary": is_binary,
                    "remediacao": (
                        "Remove firmware download endpoints from public access. "
                        "Require authentication for firmware downloads. "
                        "Serve firmware over HTTPS with signature verification."
                    ),
                })

            elif resp.status_code in (401, 403):
                findings.append({
                    "tipo": "FIRMWARE_ENDPOINT_PROTECTED",
                    "severidade": "INFO",
                    "titulo": f"Firmware endpoint exists (protected): {path}",
                    "descricao": f"Firmware endpoint {path} returned HTTP {resp.status_code} — exists but requires auth.",
                    "endpoint": url,
                    "status_code": resp.status_code,
                    "remediacao": "Ensure firmware endpoints use strong authentication and are not accessible via default credentials.",
                })

        except requests.RequestException:
            continue

    return findings


def _check_version_disclosure(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Detect firmware version disclosure in responses."""
    findings: list[dict[str, Any]] = []
    check_urls = [
        f"{base_url}/",
        f"{base_url}/status",
        f"{base_url}/info",
        f"{base_url}/version",
        f"{base_url}/api/version",
        f"{base_url}/api/info",
        f"{base_url}/system/info",
        f"{base_url}/device/info",
    ]

    for url in check_urls:
        try:
            resp = session.get(url, timeout=6, allow_redirects=False)
            if resp.status_code != 200:
                continue

            text = resp.text
            headers_text = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
            combined = f"{text} {headers_text}"

            for pattern in VERSION_PATTERNS:
                matches = re.findall(pattern, combined)
                if matches:
                    findings.append({
                        "tipo": "VERSION_DISCLOSURE",
                        "severidade": "MEDIO",
                        "titulo": f"Firmware version disclosed at {url}",
                        "descricao": (
                            f"Version information detected: {matches[:3]}. "
                            "Firmware version disclosure enables targeted attacks against known CVEs."
                        ),
                        "endpoint": url,
                        "versions_found": matches[:5],
                        "remediacao": (
                            "Remove version information from public endpoints. "
                            "Use obfuscated version identifiers internally."
                        ),
                    })
                    break  # One finding per URL

        except requests.RequestException:
            continue

    return findings


def _check_update_mechanism(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Test firmware update mechanism for security issues."""
    findings: list[dict[str, Any]] = []

    update_endpoints = ["/api/update", "/api/firmware/update", "/update", "/firmware/update", "/ota/update"]

    for path in update_endpoints:
        try:
            url = f"{base_url}{path}"
            # POST to update endpoints to test for CSRF / auth bypass
            resp = session.post(url, timeout=8, allow_redirects=False, data={})

            if resp.status_code == 200:
                body_lower = resp.text[:2000].lower()

                if any(kw in body_lower for kw in ("update", "upload", "firmware", "upgrade", "version")):
                    findings.append({
                        "tipo": "UPDATE_NO_AUTH",
                        "severidade": "CRITICO",
                        "titulo": f"Firmware update endpoint accessible without auth: {path}",
                        "descricao": (
                            f"Firmware update endpoint {path} accepted a POST request (HTTP {resp.status_code}) "
                            "without authentication. An attacker may push malicious firmware."
                        ),
                        "endpoint": url,
                        "remediacao": (
                            "Require strong authentication for firmware updates. "
                            "Implement firmware signing and verification. "
                            "Add CSRF protection to update endpoints."
                        ),
                    })

            # Check response headers for insecure update indicators
            resp_get = session.get(url, timeout=6, allow_redirects=False)
            combined = f"{resp_get.text} {' '.join(f'{k}: {v}' for k, v in resp_get.headers.items())}".lower()

            for indicator in INSECURE_UPDATE_INDICATORS:
                if indicator in combined:
                    findings.append({
                        "tipo": "INSECURE_UPDATE",
                        "severidade": "ALTO",
                        "titulo": f"Insecure update indicator: {indicator}",
                        "descricao": (
                            f"Firmware update response contains '{indicator}'. "
                            "Firmware updates should use HTTPS with signature verification."
                        ),
                        "endpoint": url,
                        "indicator": indicator,
                        "remediacao": (
                            "Enforce HTTPS for all firmware downloads. "
                            "Implement cryptographic signature verification for firmware images. "
                            "Add rollback protection."
                        ),
                    })

        except requests.RequestException:
            continue

    return findings


def _check_hardcoded_credentials(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Check firmware endpoints for hardcoded credentials."""
    findings: list[dict[str, Any]] = []

    check_paths = [
        "/firmware", "/firmware/info", "/firmware/config",
        "/config", "/config/firmware", "/device/config",
        "/admin/config", "/system/config", "/backup",
        "/backup/config", "/export", "/export/config",
    ]

    for path in check_paths:
        try:
            url = f"{base_url}{path}"
            resp = session.get(url, timeout=6, allow_redirects=False)

            if resp.status_code != 200:
                continue

            text = resp.text
            for pattern in CREDENTIAL_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    # Redact actual values
                    redacted = [re.sub(r"[:=]\s*[\"']?(\S+)", ": [REDACTED]", m) for m in matches[:3]]

                    findings.append({
                        "tipo": "HARDCODED_CREDENTIAL",
                        "severidade": "CRITICO",
                        "titulo": f"Hardcoded credentials in {path}",
                        "descricao": (
                            f"Firmware endpoint {path} contains credential patterns: {redacted}. "
                            "Hardcoded credentials in firmware are a critical security risk."
                        ),
                        "endpoint": url,
                        "patterns_matched": redacted,
                        "remediacao": (
                            "Remove all hardcoded credentials from firmware. "
                            "Use secure credential storage (TPM, secure enclave). "
                            "Force password change on first use."
                        ),
                    })

        except requests.RequestException:
            continue

    return findings


def _check_debug_interfaces(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Detect exposed debug interfaces (JTAG, UART, serial, etc.)."""
    findings: list[dict[str, Any]] = []

    for path in DEBUG_INTERFACE_PATHS:
        try:
            url = f"{base_url}{path}"
            resp = session.get(url, timeout=5, allow_redirects=False)

            if resp.status_code == 200:
                body_lower = resp.text[:1500].lower()

                # Classify severity
                severity = "MEDIO"
                if any(kw in body_lower for kw in ("jtag", "uart", "serial", "swd", "debug", "memory", "register")):
                    severity = "CRITICO"
                elif any(kw in body_lower for kw in ("shell", "console", "terminal", "cli")):
                    severity = "CRITICO"
                elif any(kw in body_lower for kw in ("proc", "sys", "kernel", "hardware")):
                    severity = "ALTO"
                elif any(kw in body_lower for kw in ("diagnostic", "diag", "test")):
                    severity = "MEDIO"

                findings.append({
                    "tipo": "DEBUG_INTERFACE",
                    "severidade": severity,
                    "titulo": f"Debug interface exposed: {path}",
                    "descricao": (
                        f"Debug/hardware interface at {path} returned HTTP 200. "
                        f"Preview: {resp.text[:200]}..."
                    ),
                    "endpoint": url,
                    "remediacao": (
                        "Disable all debug interfaces in production firmware. "
                        "Require physical access (JTAG fuse, secure boot). "
                        "Remove diagnostic endpoints from release builds."
                    ),
                })

        except requests.RequestException:
            continue

    # Check common network debug ports via banners
    debug_port_indicators = {
        23: ("TELNET", "CRITICO", "Telnet is an unencrypted debug protocol. Disable in production."),
        21: ("FTP", "ALTO", "FTP exposes firmware transfer. Use SCP/SFTP instead."),
        69: ("TFTP", "CRITICO", "TFTP has no authentication. Disable and use secure alternatives."),
        5000: ("UPnP/Web", "MEDIO", "Common embedded debug port. Verify it's intentional."),
        8080: ("Alt-HTTP", "BAIXO", "Alternative HTTP port may host debug interface."),
        9000: ("Debug-Console", "MEDIO", "Common debug console port. Verify it's secured."),
    }

    for port, (name, severity, desc) in debug_port_indicators.items():
        if port in ports:
            findings.append({
                "tipo": "DEBUG_PORT",
                "severidade": severity,
                "titulo": f"Debug port open: {port} ({name})",
                "descricao": desc,
                "port": port,
                "service": name,
                "banner": banners.get(str(port), "N/A"),
                "remediacao": f"Disable {name} service. Use SSH (port 22) with key-based auth for remote access.",
            })

    return findings


def run(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[str, str],
    context: dict | None = None,
) -> dict[str, Any] | None:
    """Main plugin entry point — Firmware analysis."""
    resultados: list[dict[str, Any]] = []

    scheme = "https" if 443 in ports else "http"
    primary_port = 443 if 443 in ports else (ports[0] if ports else 80)
    base_url = f"{scheme}://{target}" if primary_port in (80, 443) else f"{scheme}://{target}:{primary_port}"

    session = requests.Session()
    session.headers.update({
        "Accept": "text/html, application/json, */*",
        "User-Agent": "Mozilla/5.0 (Linux; rv:109.0) Gecko/20100101 Firefox/115.0",
    })

    try:
        # 1. Firmware endpoint discovery
        resultados.extend(_check_firmware_endpoints(target, base_url, session))

        # 2. Version disclosure
        resultados.extend(_check_version_disclosure(target, base_url, session))

        # 3. Update mechanism vulnerabilities
        resultados.extend(_check_update_mechanism(target, base_url, session))

        # 4. Hardcoded credentials
        resultados.extend(_check_hardcoded_credentials(target, base_url, session))

        # 5. Debug interfaces
        resultados.extend(_check_debug_interfaces(target, base_url, session))

        if not resultados:
            return None

        severities = [r["severidade"] for r in resultados]
        crit = severities.count("CRITICO")
        alto = severities.count("ALTO")

        resultados.insert(0, {
            "tipo": "RESUMO",
            "severidade": "CRITICO" if crit > 0 else ("ALTO" if alto > 0 else "MEDIO"),
            "titulo": f"Firmware Analysis — {len(resultados) - 1} findings",
            "descricao": (
                f"Firmware security analysis of {base_url} found "
                f"{crit} critical, {alto} high, "
                f"{severities.count('MEDIO')} medium, "
                f"{severities.count('BAIXO')} low, "
                f"{severities.count('INFO')} info findings."
            ),
            "total_resultados": len(resultados) - 1,
            "remediacao": (
                "Implement secure boot chain, firmware signing with X.509 certificates, "
                "disable all debug interfaces in production, remove hardcoded credentials, "
                "enforce HTTPS with certificate pinning for OTA updates."
            ),
        })

        return {"plugin": "firmware_analysis", "resultados": resultados}

    except Exception as e:
        logger.error(f"Firmware analysis failed for {target}: {e}")
        return {
            "plugin": "firmware_analysis",
            "resultados": [{
                "tipo": "ERRO",
                "severidade": "INFO",
                "titulo": "Analysis error",
                "descricao": f"Firmware analysis failed: {e}",
                "remediacao": "N/A",
            }],
        }
