# plugins/cors_checker.py
def run(target, ip, open_ports, banners):
    """
    CORS Misconfiguration Checker.
    2026 Intel: wildcard + credentials, null origin, regex bypass,
    subdomain trust, pre-flight bypass, CRLF→CORS injection chain.
    """
    import requests

    pages = ["/", "/api/", "/api/v1/", "/api/v1/users", "/login",
             "/api/v1/me", "/api/v1/config", "/graphql"]
    vulns = []

    test_origins = [
        ("https://evil.com", "ARBITRARY_ORIGIN"),
        ("null", "NULL_ORIGIN"),
        (f"https://{target}.evil.com", "SUFFIX_MATCH"),
        (f"https://evil-{target}", "PREFIX_MATCH"),
        (f"https://sub.{target}", "SUBDOMAIN"),
        ("https://evil.com%0d%0a", "CRLF_ORIGIN"),
        (f"https://{target}%60.evil.com", "BACKTICK_BYPASS"),
        ("https://evil.com%00.trusted.com", "NULL_BYTE_ORIGIN"),
    ]

    for page in pages:
        url = f"http://{target}{page}"
        for origin, method in test_origins:
            try:
                resp = requests.get(url, headers={"Origin": origin}, timeout=5)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*" and acac == "true":
                    vulns.append({
                        "tipo": "CORS_WILDCARD_CREDENTIALS", "pagina": page,
                        "origin": origin, "severidade": "CRITICO",
                        "descricao": "Wildcard + credentials — full account takeover!"
                    })
                elif acao == origin or origin in acao:
                    sev = "ALTO" if acac == "true" else "MEDIO"
                    vulns.append({
                        "tipo": "CORS_MISCONFIGURATION", "metodo": method,
                        "pagina": page, "origin_refletido": acao,
                        "credentials": acac, "severidade": sev,
                    })
                    break
            except Exception:
                continue

        # Pre-flight check
        try:
            resp = requests.options(url,
                headers={"Origin": "https://evil.com",
                          "Access-Control-Request-Method": "PUT",
                          "Access-Control-Request-Headers": "X-Custom"}, timeout=5)
            methods = resp.headers.get("Access-Control-Allow-Methods", "")
            if "PUT" in methods or "DELETE" in methods:
                vulns.append({
                    "tipo": "CORS_DANGEROUS_METHODS", "pagina": page,
                    "metodos": methods, "severidade": "MEDIO",
                })
        except Exception:
            pass

    return {"plugin": "cors_checker", "resultados": vulns if vulns else "CORS configurado corretamente"}
