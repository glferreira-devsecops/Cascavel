# plugins/open_redirect.py
def run(target, ip, open_ports, banners):
    """
    Scanner de Open Redirect: detecta redirecionamentos abertos.
    Testa parâmetros comuns com URLs externas para verificar se o servidor redireciona.
    """
    import requests

    params = ["url", "redirect", "next", "redir", "return", "returnTo", "goto", "link",
              "out", "view", "to", "ref", "continue", "dest", "destination", "target"]
    evil_urls = ["https://evil.com", "//evil.com", "https://evil.com%00.legitimate.com"]

    vulns = []

    for param in params:
        for evil in evil_urls:
            url = f"http://{target}/?{param}={evil}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if resp.status_code in [301, 302, 303, 307, 308]:
                    if "evil.com" in location:
                        vulns.append({
                            "tipo": "OPEN_REDIRECT",
                            "parametro": param,
                            "payload": evil,
                            "location_header": location,
                            "status_http": resp.status_code,
                            "severidade": "ALTO",
                        })
                # Verificar meta refresh ou JS redirect
                elif resp.status_code == 200 and "evil.com" in resp.text:
                    if any(x in resp.text.lower() for x in ["meta http-equiv", "window.location", "document.location"]):
                        vulns.append({
                            "tipo": "OPEN_REDIRECT_JS",
                            "parametro": param,
                            "payload": evil,
                            "status_http": resp.status_code,
                            "severidade": "MEDIO",
                        })
            except requests.Timeout:
                continue
            except Exception:
                continue

    return {
        "plugin": "open_redirect",
        "resultados": vulns if vulns else "Nenhum open redirect detectado"
    }
