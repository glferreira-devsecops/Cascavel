# plugins/cors_checker.py — Cascavel 2026 Intelligence
import requests

PAGES = [
    "/",
    "/api/",
    "/api/v1/",
    "/api/v1/users",
    "/login",
    "/api/v1/me",
    "/api/v1/config",
    "/graphql",
    "/api/v2/",
    "/api/profile",
    "/api/admin",
    "/api/v1/settings",
]


# ──────────── ORIGIN BYPASS VARIANTS ────────────
def _get_test_origins(target):
    return [
        ("https://evil.com", "ARBITRARY_ORIGIN"),
        ("null", "NULL_ORIGIN"),
        (f"https://{target}.evil.com", "SUFFIX_MATCH"),
        (f"https://evil-{target}", "PREFIX_MATCH"),
        (f"https://sub.{target}", "SUBDOMAIN_TRUST"),
        ("https://evil.com%0d%0a", "CRLF_ORIGIN"),
        (f"https://{target}%60.evil.com", "BACKTICK_BYPASS"),
        ("https://evil.com%00.trusted.com", "NULL_BYTE_ORIGIN"),
        (f"https://{target}@evil.com", "AT_SIGN_BYPASS"),
        ("https://evil.com%09", "TAB_BYPASS"),
        (f"http://{target}", "HTTP_DOWNGRADE"),
        (f"https://evil.com#{target}", "FRAGMENT_BYPASS"),
        ("https://evil%2ecom", "ENCODED_DOT"),
        ("https://EVIL.COM", "UPPERCASE"),
        (f"https://{target}%252eevil.com", "DOUBLE_ENCODE"),
    ]


def _test_origin_reflection(target, page, origins):
    """Testa se o servidor reflete origins arbitrários."""
    vulns = []
    for origin, method in origins:
        url = f"http://{target}{page}"
        try:
            resp = requests.get(url, headers={"Origin": origin}, timeout=5)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                vulns.append(
                    {
                        "tipo": "CORS_WILDCARD_CREDENTIALS",
                        "pagina": page,
                        "origin": origin,
                        "severidade": "CRITICO",
                        "descricao": "Wildcard + credentials — full account takeover!",
                    }
                )
                return vulns

            if acao == origin or (origin in acao and method != "SUBDOMAIN_TRUST"):
                sev = "CRITICO" if acac == "true" else "ALTO"
                vulns.append(
                    {
                        "tipo": "CORS_ORIGIN_REFLECTED",
                        "metodo": method,
                        "pagina": page,
                        "origin_refletido": acao,
                        "credentials": acac,
                        "severidade": sev,
                        "descricao": f"Origin arbitrário refletido via {method}!",
                    }
                )
                break
        except Exception as e:
            vulns.append({"tipo": "SILENT_ERROR", "severidade": "INFO", "descricao": f"Falha na requisicao: {str(e)}"})
            break
    return vulns


def _test_preflight(target, page):
    """Verifica preflight CORS para dangerous methods e headers."""
    vulns = []
    try:
        resp = requests.options(
            f"http://{target}{page}",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom, Authorization",
            },
            timeout=5,
        )
        methods = resp.headers.get("Access-Control-Allow-Methods", "")
        headers = resp.headers.get("Access-Control-Allow-Headers", "")

        dangerous_methods = [m for m in ["PUT", "DELETE", "PATCH"] if m in methods]
        if dangerous_methods:
            vulns.append(
                {
                    "tipo": "CORS_DANGEROUS_METHODS",
                    "pagina": page,
                    "metodos": dangerous_methods,
                    "severidade": "ALTO",
                    "descricao": f"CORS permite métodos destrutivos: {', '.join(dangerous_methods)}",
                }
            )

        if "*" in headers or "authorization" in headers.lower():
            vulns.append(
                {
                    "tipo": "CORS_ALLOWS_AUTH_HEADER",
                    "pagina": page,
                    "headers_permitidos": headers[:100],
                    "severidade": "ALTO",
                    "descricao": "CORS permite Authorization header — token exfiltration!",
                }
            )
    except Exception as e:
        vulns.append({"tipo": "SILENT_ERROR", "severidade": "INFO", "descricao": f"Falha de preflight: {str(e)}"})
    return vulns


def _test_vary_header(target, page):
    """Verifica se Vary: Origin está presente (cache poisoning prevention)."""
    try:
        resp = requests.get(f"http://{target}{page}", headers={"Origin": "https://test.com"}, timeout=5)
        vary = resp.headers.get("Vary", "")
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao and acao != "*" and "Origin" not in vary:
            return {
                "tipo": "CORS_MISSING_VARY",
                "pagina": page,
                "severidade": "MEDIO",
                "descricao": "CORS reflete origin sem Vary: Origin — cache poisoning possível!",
            }
    except Exception as e:
        return {"tipo": "SILENT_ERROR", "severidade": "INFO", "descricao": f"Falha no teste Vary: {str(e)}"}
    return None


def _test_expose_headers(target, page):
    """Verifica se headers sensíveis são expostos via CORS."""
    try:
        resp = requests.get(f"http://{target}{page}", headers={"Origin": "https://evil.com"}, timeout=5)
        exposed = resp.headers.get("Access-Control-Expose-Headers", "")
        sensitive = [
            h for h in ["Authorization", "X-API-Key", "Set-Cookie", "X-CSRF-Token"] if h.lower() in exposed.lower()
        ]
        if sensitive:
            return {
                "tipo": "CORS_EXPOSES_SENSITIVE_HEADERS",
                "pagina": page,
                "headers": sensitive,
                "severidade": "ALTO",
                "descricao": f"CORS expõe headers sensíveis: {', '.join(sensitive)}",
            }
    except Exception as e:
        return {"tipo": "SILENT_ERROR", "severidade": "INFO", "descricao": f"Falha de exposicao de header: {str(e)}"}
    return None


def _test_max_age(target, page):
    """Verifica se preflight cache é excessivamente longo."""
    try:
        resp = requests.options(
            f"http://{target}{page}",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        max_age = resp.headers.get("Access-Control-Max-Age", "")
        if max_age and int(max_age) > 86400:
            return {
                "tipo": "CORS_EXCESSIVE_MAX_AGE",
                "pagina": page,
                "max_age": max_age,
                "severidade": "BAIXO",
                "descricao": f"Preflight cache {max_age}s (> 24h) — mudanças de policy demoram a propagar",
            }
    except Exception as e:
        return {"tipo": "SILENT_ERROR", "severidade": "INFO", "descricao": f"Falha no max-age: {str(e)}"}
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner CORS 2026-Grade — Origin Reflection, Preflight, Cache Poisoning.

    Técnicas: 15 origin bypass variants (null/suffix/prefix/CRLF/backtick/at-sign/
    double-encode/uppercase/HTTP downgrade), preflight method/header analysis,
    Vary: Origin missing (cache poisoning), sensitive header exposure,
    excessive max-age, Authorization header leak detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    origins = _get_test_origins(target)

    for page in PAGES:
        vulns.extend(_test_origin_reflection(target, page, origins))
        vulns.extend(_test_preflight(target, page))

        vary = _test_vary_header(target, page)
        if vary:
            vulns.append(vary)

        expose = _test_expose_headers(target, page)
        if expose:
            vulns.append(expose)

        max_age = _test_max_age(target, page)
        if max_age:
            vulns.append(max_age)

    return {
        "plugin": "cors_checker",
        "versao": "2026.1",
        "tecnicas": [
            "origin_reflection",
            "null_origin",
            "prefix_suffix",
            "crlf_origin",
            "preflight_analysis",
            "vary_missing",
            "exposed_headers",
            "auth_header_leak",
            "max_age",
        ],
        "resultados": vulns if vulns else "CORS configurado corretamente",
    }
