# plugins/open_redirect.py — Cascavel 2026 Intelligence

import urllib.parse

import requests

PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "goto",
    "dest",
    "continue",
    "forward",
    "return_url",
    "redirect_uri",
    "callback",
    "rurl",
    "target",
    "out",
    "redir",
    "link",
    "ref",
    "return_to",
    "checkout_url",
    "success_url",
    "failure_url",
    "logout_redirect",
]


# ──────────── REDIRECT PAYLOADS ────────────
def _get_payloads(target):
    return [
        ("https://evil.com", "DIRECT"),
        ("//evil.com", "PROTOCOL_RELATIVE"),
        ("https://evil.com%2F%2F", "DOUBLE_ENCODE"),
        ("/\\evil.com", "BACKSLASH"),
        ("https://evil.com%00.trusted.com", "NULL_BYTE"),
        ("https://trusted.com@evil.com", "AUTHORITY_BYPASS"),
        ("https://evil.com#trusted.com", "FRAGMENT"),
        ("https://evil.com?.trusted.com", "QUERY_BYPASS"),
        (f"https://{target}.evil.com", "SUBDOMAIN_MATCH"),
        ("javascript:alert(1)", "JAVASCRIPT_URI"),
        ("data:text/html,<h1>Redirect</h1>", "DATA_URI"),
        ("https://evil.com/%2e%2e/", "DOT_ENCODED"),
        ("https:\\\\evil.com", "DOUBLE_BACKSLASH"),
        ("https:evil.com", "SCHEME_COLON"),
        # 2026 additions
        ("https://evil.com/..%252f", "DOUBLE_DOUBLE_ENCODE"),
        ("/%0d%0aLocation:%20https://evil.com", "CRLF_REDIRECT"),
        ("https://evil。com", "UNICODE_DOT"),
        (f"https://{target}%252f@evil.com", "ENCODED_SLASH_AT"),
        ("///evil.com", "TRIPLE_SLASH"),
        ("\\\\evil.com", "UNC_PATH"),
        ("https://evil.com%23.trusted.com", "ENCODED_HASH"),
        (f"https://{target}:@evil.com", "COLON_AT"),
        ("https://evil.com%0a", "LF"),
    ]


JS_REDIRECT_PATTERNS = [
    "window.location",
    "location.href",
    "location.replace",
    "document.location",
    "window.open",
    "location.assign",
]


def _verify_waf_blind_reflection(target, param):
    """Verifica se o payload é refletido cegamente no HTML, causando FPs em JS/Meta redirect."""
    junk = "http://cascavel_junk_reflection_123.com"
    url = f"http://{target}/?{param}={junk}"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if junk in resp.text:
            return True
    except Exception:
        pass
    return False


def _test_get_redirect(target, param, payload, method, reflects_blindly):
    """Testa open redirect via GET parameter."""
    url = f"http://{target}/?{param}={payload}"
    try:
        resp = requests.get(url, timeout=6, allow_redirects=False)

        # HTTP redirect
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("Location", "")

            # Verifica se evil.com é o domínio real
            is_evil = False
            if location.startswith("javascript:"):
                is_evil = True
            elif "evil.com" in location:
                try:
                    parsed = urllib.parse.urlparse(location)
                    if parsed.netloc and "evil.com" in parsed.netloc:
                        is_evil = True
                    elif not parsed.scheme and location.startswith("//evil.com"):
                        is_evil = True
                except Exception:
                    is_evil = "evil.com" in location

            if is_evil:
                sev = "CRITICO" if "javascript:" in location else "ALTO"
                return {
                    "tipo": "OPEN_REDIRECT",
                    "metodo": method,
                    "parametro": param,
                    "severidade": sev,
                    "location": location[:100],
                    "descricao": f"Open redirect via {method}!",
                }

        # JS redirect
        if resp.status_code == 200 and not reflects_blindly:
            if any(p in resp.text for p in JS_REDIRECT_PATTERNS) and "evil.com" in resp.text:
                return {
                    "tipo": "OPEN_REDIRECT_JS",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "ALTO",
                    "descricao": "JavaScript-based redirect com payload refletido!",
                }

            # Meta refresh
            if 'http-equiv="refresh"' in resp.text.lower() and "evil.com" in resp.text:
                return {
                    "tipo": "META_REFRESH_REDIRECT",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "MEDIO",
                }
    except Exception:
        pass
    return None


def _test_post_redirect(target):
    """Testa open redirect via POST body."""
    vulns = []
    post_paths = ["/login", "/auth", "/api/login", "/account/login"]
    for path in post_paths:
        try:
            resp = requests.post(
                f"http://{target}{path}",
                data={"username": "test", "password": "test", "next": "https://evil.com"},
                timeout=5,
                allow_redirects=False,
            )
            if resp.status_code in [301, 302, 303, 307]:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulns.append(
                        {
                            "tipo": "OPEN_REDIRECT_POST",
                            "path": path,
                            "severidade": "ALTO",
                            "descricao": "Open redirect via POST body redirect parameter!",
                        }
                    )
        except Exception:
            continue
    return vulns


def _test_header_redirect(target):
    """Testa open redirect via Referer header."""
    vulns = []
    try:
        resp = requests.get(
            f"http://{target}/logout",
            headers={"Referer": "https://evil.com"},
            timeout=5,
            allow_redirects=False,
        )
        if resp.status_code in [301, 302, 303, 307]:
            location = resp.headers.get("Location", "")
            if "evil.com" in location:
                vulns.append(
                    {
                        "tipo": "OPEN_REDIRECT_REFERER",
                        "severidade": "MEDIO",
                        "descricao": "Open redirect via Referer header!",
                    }
                )
    except Exception:
        pass
    return vulns


def _test_path_redirect(target):
    """Testa open redirect via path-based redirect."""
    vulns = []
    path_payloads = [
        f"http://{target}//evil.com",
        f"http://{target}/redirect/https://evil.com",
        f"http://{target}/r?url=https://evil.com",
    ]
    for url in path_payloads:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in [301, 302, 303, 307]:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulns.append(
                        {
                            "tipo": "OPEN_REDIRECT_PATH",
                            "url": url[:80],
                            "severidade": "ALTO",
                            "descricao": "Open redirect via URL path!",
                        }
                    )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Open Redirect 2026-Grade — GET, POST, Header, Path-Based.

    Técnicas: 23 payloads (protocol-relative/backslash/null-byte/authority/
    fragment/Unicode dot/UNC path/CRLF/triple-slash/encoded-hash/colon-at),
    GET parameter injection (21 params), POST body redirect,
    Referer header redirect, path-based redirect, JS redirect detection
    (window.location/location.href/location.replace/window.open),
    meta refresh detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    payloads = _get_payloads(target)

    for param in PARAMS:
        reflects_blindly = _verify_waf_blind_reflection(target, param)

        for payload, method in payloads:
            result = _test_get_redirect(target, param, payload, method, reflects_blindly)
            if result:
                vulns.append(result)
                break
        if len(vulns) > 15:
            break

    vulns.extend(_test_post_redirect(target))
    vulns.extend(_test_header_redirect(target))
    vulns.extend(_test_path_redirect(target))

    return {
        "plugin": "open_redirect",
        "versao": "2026.1",
        "tecnicas": [
            "get_param",
            "post_body",
            "referer_header",
            "path_redirect",
            "js_redirect",
            "meta_refresh",
            "protocol_relative",
            "unicode_bypass",
            "crlf_redirect",
        ],
        "resultados": vulns if vulns else "Nenhum open redirect detectado",
    }
