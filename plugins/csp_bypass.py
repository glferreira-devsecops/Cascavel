# plugins/csp_bypass.py — Cascavel 2026 Intelligence
import re

import requests

BYPASS_INDICATORS = {
    "'unsafe-inline'": ("CSP_UNSAFE_INLINE", "ALTO", "unsafe-inline permite XSS inline"),
    "'unsafe-eval'": ("CSP_UNSAFE_EVAL", "ALTO", "unsafe-eval permite eval() — XSS!"),
    "data:": ("CSP_DATA_URI", "MEDIO", "data: URI permitida — bypass via data: scheme"),
    "blob:": ("CSP_BLOB_URI", "MEDIO", "blob: URI permitida — bypass via blob: scheme"),
    "*": ("CSP_WILDCARD", "CRITICO", "Wildcard * — CSP completamente ineficaz!"),
}

# ──────────── JSONP BYPASS SOURCES ────────────
JSONP_BYPASS_DOMAINS = [
    "accounts.google.com",
    "www.google.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "unpkg.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "*.googleapis.com",
    "*.gstatic.com",
    "maps.google.com",
    "www.youtube.com",
    "*.fbcdn.net",
    "connect.facebook.net",
    "platform.linkedin.com",
]

# ──────────── ANGULAR/REACT CDN BYPASS ────────────
FRAMEWORK_BYPASS_DOMAINS = [
    ("cdnjs.cloudflare.com", "Angular/React via CDN — template injection bypass"),
    ("cdn.jsdelivr.net", "jsDelivr CDN — arbitrary JS execution"),
    ("unpkg.com", "unpkg CDN — arbitrary JS execution"),
    ("raw.githubusercontent.com", "GitHub raw — user-controlled JS execution"),
]

PAGES_TO_CHECK = ["/", "/login", "/dashboard", "/api/", "/admin"]


def _parse_csp(target):
    """Obtém e parseia CSP de múltiplas páginas."""
    results = {}
    for page in PAGES_TO_CHECK:
        try:
            resp = requests.get(f"http://{target}{page}", timeout=8)
            csp = resp.headers.get("Content-Security-Policy", "")
            csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
            meta_csp = re.findall(r'<meta[^>]*content-security-policy[^>]*content="([^"]+)"', resp.text, re.IGNORECASE)
            results[page] = {
                "csp": csp,
                "csp_ro": csp_ro,
                "meta_csp": meta_csp[0] if meta_csp else "",
            }
        except Exception:
            continue
    return results


def _parse_directives(csp_string):
    """Parseia CSP em dict de diretivas."""
    directives = {}
    for directive in csp_string.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split(None, 1)
        name = parts[0].lower()
        value = parts[1] if len(parts) > 1 else ""
        directives[name] = value
    return directives


def _analyze_directives(csp_string, page):
    """Analisa diretivas CSP para bypasses conhecidos."""
    vulns = []
    if not csp_string:
        vulns.append(
            {
                "tipo": "CSP_AUSENTE",
                "pagina": page,
                "severidade": "ALTO",
                "descricao": "Content-Security-Policy ausente — sem proteção contra XSS!",
            }
        )
        return vulns

    directives = _parse_directives(csp_string)

    # Check unsafe keywords
    for keyword, result in BYPASS_INDICATORS.items():
        if result and keyword in csp_string:
            tipo, sev, desc = result
            vulns.append(
                {
                    "tipo": tipo,
                    "pagina": page,
                    "severidade": sev,
                    "descricao": desc,
                }
            )

    # Missing directives
    critical_missing = []
    if "default-src" not in directives and "script-src" not in directives:
        critical_missing.append("script-src")
    if "object-src" not in directives and "default-src" not in directives:
        critical_missing.append("object-src")
    if "base-uri" not in directives:
        vulns.append(
            {
                "tipo": "CSP_NO_BASE_URI",
                "pagina": page,
                "severidade": "ALTO",
                "descricao": "base-uri ausente — dangling markup + base tag injection!",
            }
        )
    if "frame-ancestors" not in directives:
        vulns.append(
            {
                "tipo": "CSP_NO_FRAME_ANCESTORS",
                "pagina": page,
                "severidade": "MEDIO",
                "descricao": "frame-ancestors ausente — clickjacking possível via CSP!",
            }
        )

    if critical_missing:
        vulns.append(
            {
                "tipo": "CSP_MISSING_DIRECTIVES",
                "pagina": page,
                "directives": critical_missing,
                "severidade": "ALTO",
            }
        )

    # JSONP bypass
    for jsonp_domain in JSONP_BYPASS_DOMAINS:
        domain = jsonp_domain.replace("*.", "")
        if domain in csp_string:
            vulns.append(
                {
                    "tipo": "CSP_JSONP_BYPASS",
                    "pagina": page,
                    "dominio": jsonp_domain,
                    "severidade": "CRITICO",
                    "descricao": f"CSP permite {jsonp_domain} — bypass via JSONP callback!",
                }
            )

    # Framework CDN bypass
    for cdn_domain, desc in FRAMEWORK_BYPASS_DOMAINS:
        if cdn_domain in csp_string:
            # Rebaixamento Anti-FP: CDNs como jsdelivr/unpkg só são altamente perigosos com unsafe-eval ou wildcards
            if "'unsafe-eval'" in csp_string or "*" in csp_string:
                sev = "ALTO"
                desc_ext = f"{desc} (Agravado por unsafe-eval/*)"
            else:
                sev = "BAIXO"
                desc_ext = f"{desc} (Risco mitigado sem unsafe-eval, possível falso positivo em apps modernas)"

            vulns.append(
                {
                    "tipo": "CSP_CDN_BYPASS",
                    "pagina": page,
                    "dominio": cdn_domain,
                    "severidade": sev,
                    "descricao": desc_ext,
                }
            )

    # strict-dynamic with unsafe-inline (makes inline noop)
    if "'strict-dynamic'" in csp_string and "'unsafe-inline'" in csp_string:
        vulns.append(
            {
                "tipo": "CSP_STRICT_DYNAMIC_INLINE",
                "pagina": page,
                "severidade": "MEDIO",
                "descricao": "strict-dynamic anula unsafe-inline — mas gadgets de parser podem bypassar!",
            }
        )

    # Nonce/hash detection and analysis
    nonces = re.findall(r"'nonce-([^']+)'", csp_string)
    if nonces:
        for nonce in nonces:
            if len(nonce) < 8:
                vulns.append(
                    {
                        "tipo": "CSP_SHORT_NONCE",
                        "pagina": page,
                        "nonce_len": len(nonce),
                        "severidade": "ALTO",
                        "descricao": f"Nonce CSP curto ({len(nonce)} chars) — brute-force possível!",
                    }
                )

    # report-uri endpoint
    if "report-uri" in csp_string or "report-to" in csp_string:
        report_match = re.search(r"report-uri\s+(\S+)", csp_string)
        if report_match:
            vulns.append(
                {
                    "tipo": "CSP_REPORT_URI_EXPOSED",
                    "pagina": page,
                    "uri": report_match.group(1)[:80],
                    "severidade": "BAIXO",
                    "descricao": "CSP report-uri exposto — information gathering",
                }
            )

    return vulns


def _check_report_only(csp_ro, page):
    """Verifica se CSP está em modo Report-Only."""
    if csp_ro:
        return [
            {
                "tipo": "CSP_REPORT_ONLY",
                "pagina": page,
                "severidade": "ALTO",
                "descricao": "CSP em Report-Only — NÃO bloqueia ataques!",
            }
        ]
    return []


def _check_meta_vs_header(header_csp, meta_csp, page):
    """Verifica conflitos entre CSP header e meta tag."""
    vulns = []
    if header_csp and meta_csp and header_csp != meta_csp:
        vulns.append(
            {
                "tipo": "CSP_HEADER_META_CONFLICT",
                "pagina": page,
                "severidade": "MEDIO",
                "descricao": "CSP header e meta tag diferentes — browser aplica ambos, possível confusão!",
            }
        )
    if meta_csp and not header_csp:
        vulns.append(
            {
                "tipo": "CSP_META_ONLY",
                "pagina": page,
                "severidade": "MEDIO",
                "descricao": "CSP apenas via meta tag — não protege contra frames/subresources!",
            }
        )
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner CSP Bypass 2026-Grade — JSONP, CDN, Nonce, base-uri, strict-dynamic.

    Técnicas: 15 JSONP bypass domains, 4 framework CDN bypass, directive analysis
    (unsafe-inline/eval/data/blob/wildcard), missing directives (base-uri/frame-ancestors/
    object-src), strict-dynamic conflict, nonce length check, report-only detection,
    meta vs header conflict, report-uri exposure, multi-page analysis.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    page_results = _parse_csp(target)

    for page, data in page_results.items():
        # Analyze header CSP
        vulns.extend(_analyze_directives(data["csp"], page))

        # Check report-only
        vulns.extend(_check_report_only(data["csp_ro"], page))

        # Meta vs header conflict
        vulns.extend(_check_meta_vs_header(data["csp"], data["meta_csp"], page))

    return {
        "plugin": "csp_bypass",
        "versao": "2026.1",
        "tecnicas": [
            "jsonp_bypass",
            "cdn_bypass",
            "base_uri_missing",
            "frame_ancestors",
            "strict_dynamic",
            "nonce_analysis",
            "report_only",
            "meta_conflict",
            "directive_analysis",
        ],
        "resultados": vulns if vulns else "CSP configurada corretamente",
    }
