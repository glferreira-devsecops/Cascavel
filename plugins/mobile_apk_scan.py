"""
Mobile APK Scan — Detect mobile-specific API endpoints, headers,
versioning issues, certificate pinning bypass, and debug endpoints.
"""

import logging
import re
from typing import Any

import requests

logger = logging.getLogger("Cascavel.Plugins.MobileAPKScan")

# Common mobile API path patterns
MOBILE_API_PATHS: list[str] = [
    "/api/mobile",
    "/api/v1/mobile",
    "/api/v2/mobile",
    "/api/app",
    "/api/android",
    "/api/ios",
    "/mobile/api",
    "/m/api",
    "/app/api",
    "/api/native",
    "/api/device",
    "/api/devices",
    "/api/push",
    "/api/notifications",
    "/api/location",
    "/api/geo",
    "/api/contacts",
    "/api/gallery",
    "/api/camera",
    "/api/files/upload",
    "/api/sync",
    "/api/offline",
    "/graphql/mobile",
    "/api/graphql",
    "/api/rest/mobile",
    "/api/gateway",
    "/api/bff",
    "/api/internal/mobile",
]

# Debug / development endpoints
DEBUG_PATHS: list[str] = [
    "/api/debug",
    "/api/test",
    "/api/dev",
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/debug/requests",
    "/status",
    "/health",
    "/healthz",
    "/readyz",
    "/metrics",
    "/info",
    "/env",
    "/config",
    "/admin/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/openapi.json",
    "/.well-known/openapi",
    "/redoc",
    "/graphiql",
    "/playground",
    "/voyager",
    "/mobile/debug",
    "/mobile/config",
    "/mobile/flags",
    "/api/feature-flags",
    "/api/remote-config",
    "/api/experiments",
    "/api/ab-test",
]

# Mobile-specific headers
MOBILE_HEADERS: dict[str, str] = {
    "X-Requested-With": "com.example.app",
    "X-Platform": "android",
    "X-App-Version": "1.0.0",
    "X-Device-Id": "test-device-001",
    "X-OS-Version": "Android 14",
    "X-API-Key": "mobile-client-key",
    "X-Client-Type": "mobile",
    "X-Device-Model": "Pixel 8",
    "X-App-Build": "100",
    "X-Bundle-Id": "com.example.app",
    "User-Agent": "okhttp/4.12.0",
}

# API version patterns
VERSION_PATTERNS: list[str] = [
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/api/v5",
    "/api/1.0",
    "/api/2.0",
    "/api/v1.0",
    "/api/v2.0",
    "/api/beta",
    "/api/alpha",
    "/api/staging",
    "/api/canary",
    "/api/next",
    "/api/deprecated",
    "/api/internal",
    "/api/legacy",
    "/api/unstable",
]

# Certificate pinning bypass indicators
PINNING_BYPASS_HEADERS: list[str] = [
    "X-Debug-SSL",
    "X-SSL-Pinning",
    "X-Cert-Pinning",
    "X-Pinning-Policy",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "Expect-CT",
]

# Trust-All / accept-all TLS indicators in response
TRUST_ALL_INDICATORS: list[str] = [
    "trust-all-certificates",
    "accept-all-certs",
    "ssl-pinning-disabled",
    "certificate-verification-disabled",
    "insecure-mode",
]


def _check_mobile_api_paths(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Probe for mobile API endpoints."""
    findings: list[dict[str, Any]] = []

    for path in MOBILE_API_PATHS:
        try:
            url = f"{base_url}{path}"
            resp = session.get(url, timeout=8, allow_redirects=False)

            if resp.status_code in (200, 201, 204, 206):
                findings.append({
                    "tipo": "MOBILE_ENDPOINT",
                    "severidade": "MEDIO",
                    "titulo": f"Mobile API endpoint exposed: {path}",
                    "descricao": (
                        f"Mobile API endpoint {path} returned HTTP {resp.status_code}. "
                        f"Mobile-specific endpoints may have weaker security controls than web APIs."
                    ),
                    "endpoint": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "remediacao": (
                        "Restrict mobile API access via mTLS, API keys, or OAuth. "
                        "Ensure mobile endpoints enforce the same authorization as web endpoints."
                    ),
                })
            elif resp.status_code == 401:
                findings.append({
                    "tipo": "MOBILE_ENDPOINT_AUTH",
                    "severidade": "BAIXO",
                    "titulo": f"Mobile API endpoint exists (auth required): {path}",
                    "descricao": f"Mobile API {path} returned 401 — endpoint exists but requires authentication.",
                    "endpoint": url,
                    "status_code": resp.status_code,
                    "remediacao": "Ensure mobile authentication uses secure token storage and certificate pinning.",
                })
            elif resp.status_code == 403 and resp.headers.get("Server"):
                findings.append({
                    "tipo": "MOBILE_ENDPOINT_FORBIDDEN",
                    "severidade": "INFO",
                    "titulo": f"Mobile API endpoint exists (forbidden): {path}",
                    "descricao": f"Mobile API {path} returned 403 — server identity confirmed.",
                    "endpoint": url,
                    "status_code": resp.status_code,
                    "remediacao": "Verify that 403 responses do not leak internal error details.",
                })

        except requests.RequestException:
            continue

    return findings


def _check_mobile_headers(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Test mobile-specific header behavior."""
    findings: list[dict[str, Any]] = []

    # Test with mobile headers vs. without
    try:
        url_normal = f"{base_url}/"
        resp_normal = session.get(url_normal, timeout=8, allow_redirects=False)
        normal_body_len = len(resp_normal.content)
        normal_status = resp_normal.status_code
    except requests.RequestException:
        return findings

    for header_name, header_value in MOBILE_HEADERS.items():
        try:
            resp = session.get(
                url_normal,
                headers={header_name: header_value},
                timeout=8,
                allow_redirects=False,
            )

            # Check if mobile header changes behavior
            if resp.status_code != normal_status:
                findings.append({
                    "tipo": "MOBILE_HEADER_DIFF",
                    "severidade": "MEDIO",
                    "titulo": f"Server behavior changes with {header_name}",
                    "descricao": (
                        f"HTTP status changed from {normal_status} to {resp.status_code} "
                        f"when {header_name}: {header_value} was sent. "
                        "Server may be leaking different content to mobile clients."
                    ),
                    "header": header_name,
                    "status_normal": normal_status,
                    "status_mobile": resp.status_code,
                    "remediacao": (
                        "Ensure server returns consistent responses regardless of client type. "
                        "Mobile-specific behavior should be behind authenticated endpoints."
                    ),
                })

            body_diff = abs(len(resp.content) - normal_body_len)
            if body_diff > 500 and resp.status_code == normal_status:
                findings.append({
                    "tipo": "MOBILE_BODY_DIFF",
                    "severidade": "BAIXO",
                    "titulo": f"Different response body with {header_name}",
                    "descricao": (
                        f"Response body differs by {body_diff} bytes when {header_name} is set. "
                        "Mobile clients may receive additional data or different page layout."
                    ),
                    "header": header_name,
                    "body_diff_bytes": body_diff,
                    "remediacao": "Audit mobile-specific response content for information disclosure.",
                })

        except requests.RequestException:
            continue

    return findings


def _check_api_versioning(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Test for API versioning issues (deprecated versions accessible)."""
    findings: list[dict[str, Any]] = []
    accessible_versions: list[str] = []

    for version_path in VERSION_PATTERNS:
        try:
            url = f"{base_url}{version_path}"
            resp = session.get(url, timeout=8, allow_redirects=False)

            if resp.status_code in (200, 201, 204):
                accessible_versions.append(version_path)

                # Deprecated/legacy/internal versions are high risk
                if any(kw in version_path for kw in ("deprecated", "legacy", "internal", "alpha", "beta", "unstable")):
                    findings.append({
                        "tipo": "API_VERSION_DEPRECATED",
                        "severidade": "ALTO",
                        "titulo": f"Deprecated API version accessible: {version_path}",
                        "descricao": (
                            f"Deprecated API version {version_path} is still accessible (HTTP {resp.status_code}). "
                            "Older API versions may lack current security controls and patches."
                        ),
                        "endpoint": url,
                        "remediacao": (
                            "Disable deprecated API versions. If required, enforce the same "
                            "authentication and rate limiting as current versions."
                        ),
                    })
                else:
                    findings.append({
                        "tipo": "API_VERSION",
                        "severidade": "BAIXO",
                        "titulo": f"API version accessible: {version_path}",
                        "descricao": f"API version {version_path} returned HTTP {resp.status_code}.",
                        "endpoint": url,
                        "remediacao": "Document active API versions and enforce version sunset policies.",
                    })

        except requests.RequestException:
            continue

    # If multiple versions accessible, flag version sprawl
    if len(accessible_versions) > 3:
        findings.append({
            "tipo": "API_VERSIONING_SPRAWL",
            "severidade": "MEDIO",
            "titulo": f"Excessive API versions exposed: {len(accessible_versions)}",
            "descricao": (
                f"Found {len(accessible_versions)} accessible API versions: "
                f"{', '.join(accessible_versions)}. "
                "Version sprawl increases attack surface and maintenance burden."
            ),
            "versions": accessible_versions,
            "remediacao": (
                "Maintain only current and N-1 API versions. "
                "Implement automated version sunset with migration guides."
            ),
        })

    return findings


def _check_cert_pinning(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Check for certificate pinning bypass opportunities."""
    findings: list[dict[str, Any]] = []

    try:
        url = f"{base_url}/"
        resp = session.get(url, timeout=8)

        # Check for HPKP / pinning headers
        for header in PINNING_BYPASS_HEADERS:
            value = resp.headers.get(header)
            if value:
                findings.append({
                    "tipo": "CERT_PINNING_HEADER",
                    "severidade": "INFO",
                    "titulo": f"Certificate pinning header detected: {header}",
                    "descricao": (
                        f"Header {header}: {value} detected. "
                        "This indicates pinning configuration that may be bypassable."
                    ),
                    "header": header,
                    "value": value,
                    "remediacao": (
                        "Use native certificate pinning (OkHttp, NSURLSession) rather than HTTP headers. "
                        "HPKP is deprecated; use Expect-CT or Certificate Transparency monitoring."
                    ),
                })

        # Check for trust-all indicators in response body or headers
        resp_text = resp.text.lower()
        header_text = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

        for indicator in TRUST_ALL_INDICATORS:
            if indicator in resp_text or indicator in header_text:
                findings.append({
                    "tipo": "TRUST_ALL_TLS",
                    "severidade": "ALTO",
                    "titulo": f"Insecure TLS indicator found: {indicator}",
                    "descricao": (
                        f"Response contains '{indicator}' — the server or client may be "
                        "configured to accept all certificates, defeating TLS protection."
                    ),
                    "remediacao": (
                        "Remove trust-all certificate configurations. "
                        "Implement proper certificate validation and pinning."
                    ),
                })

        # Check for missing security headers relevant to mobile
        mobile_security_headers = {
            "Strict-Transport-Security": "HSTS prevents SSL stripping attacks on mobile networks.",
            "X-Content-Type-Options": "Prevents MIME sniffing on mobile WebView components.",
            "Content-Security-Policy": "CSP mitigates injection attacks in mobile WebViews.",
        }
        for header, desc in mobile_security_headers.items():
            if header not in resp.headers:
                findings.append({
                    "tipo": "MISSING_SECURITY_HEADER",
                    "severidade": "MEDIO",
                    "titulo": f"Missing {header} (mobile-relevant)",
                    "descricao": f"{header} header not set. {desc}",
                    "header": header,
                    "remediacao": f"Configure {header} header on all API responses.",
                })

    except requests.RequestException as e:
        logger.debug(f"Certificate pinning check failed: {e}")

    return findings


def _check_debug_endpoints(
    target: str, base_url: str, session: requests.Session
) -> list[dict[str, Any]]:
    """Detect exposed debug and development endpoints."""
    findings: list[dict[str, Any]] = []

    for path in DEBUG_PATHS:
        try:
            url = f"{base_url}{path}"
            resp = session.get(url, timeout=6, allow_redirects=False)

            if resp.status_code == 200:
                body_lower = resp.text[:2000].lower()

                # Classify severity based on content
                severity = "MEDIO"
                if any(kw in body_lower for kw in ("password", "secret", "token", "credential", "key", "env")):
                    severity = "CRITICO"
                elif any(kw in body_lower for kw in ("debug", "trace", "stack", "exception", "error", "internal")):
                    severity = "ALTO"
                elif any(kw in body_lower for kw in ("swagger", "openapi", "api-docs", "graphiql", "playground")):
                    severity = "ALTO"
                elif any(kw in body_lower for kw in ("health", "ready", "alive", "status", "info")):
                    severity = "BAIXO"

                findings.append({
                    "tipo": "DEBUG_ENDPOINT",
                    "severidade": severity,
                    "titulo": f"Debug endpoint exposed: {path}",
                    "descricao": (
                        f"Debug/development endpoint {path} returned HTTP 200. "
                        f"Content preview: {resp.text[:200]}..."
                    ),
                    "endpoint": url,
                    "content_length": len(resp.content),
                    "remediacao": (
                        "Disable debug endpoints in production. "
                        "Restrict to internal network or VPN. "
                        "Use IP allowlisting for monitoring endpoints."
                    ),
                })

        except requests.RequestException:
            continue

    return findings


def run(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[str, str],
    context: dict | None = None,
) -> dict[str, Any] | None:
    """Main plugin entry point — Mobile application scanning."""
    resultados: list[dict[str, Any]] = []

    # Determine base URL
    scheme = "https" if 443 in ports else "http"
    primary_port = 443 if 443 in ports else (ports[0] if ports else 80)
    base_url = f"{scheme}://{target}" if primary_port in (80, 443) else f"{scheme}://{target}:{primary_port}"

    session = requests.Session()
    session.headers.update({
        "Accept": "application/json, text/html",
        "Accept-Language": "en-US,en;q=0.9",
    })

    try:
        # 1. Mobile API endpoint discovery
        mobile_endpoints = _check_mobile_api_paths(target, base_url, session)
        resultados.extend(mobile_endpoints)

        # 2. Mobile header behavior
        header_findings = _check_mobile_headers(target, base_url, session)
        resultados.extend(header_findings)

        # 3. API versioning issues
        version_findings = _check_api_versioning(target, base_url, session)
        resultados.extend(version_findings)

        # 4. Certificate pinning bypass
        pinning_findings = _check_cert_pinning(target, base_url, session)
        resultados.extend(pinning_findings)

        # 5. Debug endpoint exposure
        debug_findings = _check_debug_endpoints(target, base_url, session)
        resultados.extend(debug_findings)

        if not resultados:
            return None

        # Summary
        severities = [r["severidade"] for r in resultados]
        crit = severities.count("CRITICO")
        alto = severities.count("ALTO")

        resultados.insert(0, {
            "tipo": "RESUMO",
            "severidade": "CRITICO" if crit > 0 else ("ALTO" if alto > 0 else "MEDIO"),
            "titulo": f"Mobile APK Scan — {len(resultados) - 1} findings",
            "descricao": (
                f"Mobile security scan of {base_url} found "
                f"{crit} critical, {alto} high, "
                f"{severities.count('MEDIO')} medium, "
                f"{severities.count('BAIXO')} low, "
                f"{severities.count('INFO')} info findings."
            ),
            "total_resultados": len(resultados) - 1,
            "remediacao": (
                "Implement mobile-specific security: certificate pinning, "
                "mTLS for API access, disable deprecated API versions, "
                "remove debug endpoints in production."
            ),
        })

        return {"plugin": "mobile_apk_scan", "resultados": resultados}

    except Exception as e:
        logger.error(f"Mobile APK scan failed for {target}: {e}")
        return {
            "plugin": "mobile_apk_scan",
            "resultados": [{
                "tipo": "ERRO",
                "severidade": "INFO",
                "titulo": "Scan error",
                "descricao": f"Mobile APK scan failed: {e}",
                "remediacao": "N/A",
            }],
        }
