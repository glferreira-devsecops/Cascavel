# plugins/security_headers.py — Cascavel 2026 Intelligence
# SPDX-License-Identifier: MIT
"""
HTTP Security Headers Analyzer — OWASP Secure Headers Project compliance.

Checks 15 critical security headers against OWASP best practices.
Maps findings to CWE IDs for compliance reporting.
"""

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════════
# Header definitions: (header_name, cwe_id, severity, missing_description)
# ═══════════════════════════════════════════════════════════════════════════════
REQUIRED_HEADERS = [
    (
        "Content-Security-Policy",
        "CWE-1021",
        "ALTO",
        "CSP ausente — XSS e injeção de dados sem mitigação",
    ),
    (
        "X-Content-Type-Options",
        "CWE-16",
        "MEDIO",
        "X-Content-Type-Options ausente — MIME sniffing possível",
    ),
    (
        "X-Frame-Options",
        "CWE-1021",
        "MEDIO",
        "X-Frame-Options ausente — clickjacking possível",
    ),
    (
        "Referrer-Policy",
        "CWE-200",
        "BAIXO",
        "Referrer-Policy ausente — vazamento de URL em requests cross-origin",
    ),
    (
        "Permissions-Policy",
        "CWE-16",
        "BAIXO",
        "Permissions-Policy ausente — APIs de browser sem restrição",
    ),
    (
        "X-DNS-Prefetch-Control",
        "CWE-200",
        "INFO",
        "X-DNS-Prefetch-Control ausente — DNS prefetch pode vazar domínios visitados",
    ),
    (
        "Cross-Origin-Opener-Policy",
        "CWE-346",
        "BAIXO",
        "COOP ausente — window.opener acessível cross-origin",
    ),
    (
        "Cross-Origin-Resource-Policy",
        "CWE-346",
        "BAIXO",
        "CORP ausente — recursos podem ser lidos cross-origin (Spectre)",
    ),
    (
        "Cross-Origin-Embedder-Policy",
        "CWE-346",
        "BAIXO",
        "COEP ausente — SharedArrayBuffer e high-res timers expostos",
    ),
]

# Headers that SHOULD NOT be present (information disclosure)
DANGEROUS_HEADERS = [
    (
        "Server",
        "CWE-200",
        "BAIXO",
        "Header Server expõe software/versão — ajuda fingerprinting",
    ),
    (
        "X-Powered-By",
        "CWE-200",
        "MEDIO",
        "X-Powered-By expõe stack — facilita exploração direcionada",
    ),
    (
        "X-AspNet-Version",
        "CWE-200",
        "MEDIO",
        "X-AspNet-Version expõe versão do framework .NET",
    ),
    (
        "X-AspNetMvc-Version",
        "CWE-200",
        "MEDIO",
        "X-AspNetMvc-Version expõe versão do MVC",
    ),
    (
        "X-Generator",
        "CWE-200",
        "BAIXO",
        "X-Generator expõe CMS/framework utilizado",
    ),
]

# CSP directives that indicate weak configuration
CSP_WEAK_DIRECTIVES = {
    "unsafe-inline": ("CSP_UNSAFE_INLINE", "ALTO", "CSP permite unsafe-inline — XSS não mitigado"),
    "unsafe-eval": ("CSP_UNSAFE_EVAL", "ALTO", "CSP permite unsafe-eval — eval()/Function() habilitados"),
    "data:": ("CSP_DATA_URI", "MEDIO", "CSP permite data: URI — bypass de CSP via data: URLs"),
    "blob:": ("CSP_BLOB_URI", "BAIXO", "CSP permite blob: URI — possível bypass via Blob URLs"),
    "*": ("CSP_WILDCARD", "CRITICO", "CSP com wildcard (*) — qualquer origem permitida"),
}


def _fetch_headers(target):
    """Faz GET HTTPS e HTTP e retorna headers de ambos."""
    import requests

    headers_map = {}
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{target}",
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Cascavel/3.0 SecurityAudit"},
            )
            headers_map[scheme] = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "url_final": resp.url,
            }
        except requests.exceptions.SSLError:
            headers_map[scheme] = {"erro": "SSL handshake falhou"}
        except requests.exceptions.ConnectionError:
            headers_map[scheme] = {"erro": f"Conexão recusada ({scheme})"}
        except requests.exceptions.Timeout:
            headers_map[scheme] = {"erro": f"Timeout ({scheme})"}
        except Exception as e:
            headers_map[scheme] = {"erro": str(e)[:120]}
    return headers_map


def _analyze_csp(csp_value):
    """Analisa diretivas CSP em busca de configurações fracas."""
    vulns = []
    if not csp_value:
        return vulns

    directives = csp_value.lower()
    for weak_token, (vuln_type, severity, desc) in CSP_WEAK_DIRECTIVES.items():
        if weak_token in directives:
            vulns.append(
                {
                    "tipo": vuln_type,
                    "severidade": severity,
                    "cwe": "CWE-1021",
                    "descricao": desc,
                    "evidencia": f"CSP contém '{weak_token}'",
                }
            )

    # Check for missing default-src
    if "default-src" not in directives and "script-src" not in directives:
        vulns.append(
            {
                "tipo": "CSP_NO_DEFAULT",
                "severidade": "ALTO",
                "cwe": "CWE-1021",
                "descricao": "CSP sem default-src ou script-src — política não restritiva",
            }
        )

    return vulns


def _check_cache_headers(headers):
    """Verifica headers de cache para dados sensíveis."""
    vulns = []
    cache_control = headers.get("Cache-Control", "")
    pragma = headers.get("Pragma", "")

    if not cache_control and not pragma:
        vulns.append(
            {
                "tipo": "CACHE_NO_CONTROL",
                "severidade": "BAIXO",
                "cwe": "CWE-525",
                "descricao": "Cache-Control ausente — dados sensíveis podem ser cacheados por proxies",
            }
        )
    elif cache_control:
        cc_lower = cache_control.lower()
        if "no-store" not in cc_lower and "private" not in cc_lower:
            vulns.append(
                {
                    "tipo": "CACHE_PUBLIC",
                    "severidade": "BAIXO",
                    "cwe": "CWE-525",
                    "descricao": "Cache-Control sem no-store/private — respostas podem ser cacheadas publicamente",
                }
            )

    return vulns


def run(target, ip, open_ports, banners):
    """
    HTTP Security Headers Analyzer — OWASP Secure Headers compliance.

    Técnicas: Análise de 15 headers de segurança obrigatórios,
    detecção de headers de info disclosure (Server, X-Powered-By),
    análise profunda de CSP (unsafe-inline, unsafe-eval, wildcards),
    verificação de cache headers, mapeamento CWE para compliance.
    """
    _ = (ip, open_ports, banners)

    vulns = []
    header_data = _fetch_headers(target)

    # Use HTTPS response if available, fallback to HTTP
    primary = header_data.get("https", header_data.get("http", {}))
    if "erro" in primary:
        # Try HTTP if HTTPS failed
        primary = header_data.get("http", primary)

    if "erro" in primary:
        return {
            "plugin": "security_headers",
            "versao": "2026.1",
            "resultados": f"Não foi possível conectar: {primary['erro']}",
            "severidade": "INFO",
        }

    resp_headers = primary.get("headers", {})

    # ── Check required headers ──────────────────────────────────────────
    present = []
    missing = []
    for header_name, cwe, severity, desc in REQUIRED_HEADERS:
        value = resp_headers.get(header_name, "")
        if value:
            present.append(header_name)
        else:
            missing.append(header_name)
            vulns.append(
                {
                    "tipo": f"MISSING_{header_name.upper().replace('-', '_')}",
                    "severidade": severity,
                    "cwe": cwe,
                    "descricao": desc,
                }
            )

    # ── Check dangerous headers (info disclosure) ───────────────────────
    disclosed = []
    for header_name, cwe, severity, desc in DANGEROUS_HEADERS:
        value = resp_headers.get(header_name, "")
        if value:
            disclosed.append(f"{header_name}: {value}")
            vulns.append(
                {
                    "tipo": f"DISCLOSURE_{header_name.upper().replace('-', '_')}",
                    "severidade": severity,
                    "cwe": cwe,
                    "descricao": f"{desc} → {value}",
                }
            )

    # ── Deep CSP analysis ───────────────────────────────────────────────
    csp = resp_headers.get("Content-Security-Policy", "")
    vulns.extend(_analyze_csp(csp))

    # ── Cache headers ───────────────────────────────────────────────────
    vulns.extend(_check_cache_headers(resp_headers))

    # ── Determine overall severity ──────────────────────────────────────
    severity_order = {"CRITICO": 4, "ALTO": 3, "MEDIO": 2, "BAIXO": 1, "INFO": 0}
    max_sev = "INFO"
    for v in vulns:
        sev = v.get("severidade", "INFO")
        if severity_order.get(sev, 0) > severity_order.get(max_sev, 0):
            max_sev = sev

    score = round((len(present) / max(len(REQUIRED_HEADERS), 1)) * 100, 1)

    return {
        "plugin": "security_headers",
        "versao": "2026.1",
        "tecnicas": [
            "owasp_secure_headers",
            "csp_analysis",
            "info_disclosure",
            "cache_audit",
            "cwe_mapping",
        ],
        "score": f"{score}% ({len(present)}/{len(REQUIRED_HEADERS)} headers)",
        "headers_presentes": present,
        "headers_ausentes": missing,
        "info_disclosure": disclosed if disclosed else "Nenhum header de info disclosure",
        "csp_raw": csp if csp else "Ausente",
        "resultados": vulns if vulns else "Headers de segurança em conformidade OWASP",
        "severidade": max_sev,
    }
