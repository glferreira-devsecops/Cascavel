# plugins/web_cache_poison.py
def run(target, ip, open_ports, banners):
    """
    Scanner Web Cache Poisoning.
    Testa manipulação de cache via headers não-keyed.
    """
    import requests

    vulns = []
    canary = "cascavel-cache-poison-test"
    pages = ["/", "/index.html", "/about", "/home", "/login"]

    unkeyed_headers = [
        ("X-Forwarded-Host", canary),
        ("X-Host", canary),
        ("X-Original-URL", f"/{canary}"),
        ("X-Rewrite-URL", f"/{canary}"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto", "nothttps"),
    ]

    for page in pages:
        url = f"http://{target}{page}"

        for header_name, header_value in unkeyed_headers:
            try:
                # Enviar request com header poisoned
                resp1 = requests.get(url, headers={header_name: header_value}, timeout=5)

                # Verificar reflexão
                if canary in resp1.text or canary in str(resp1.headers):
                    # Confirmar: enviar request limpa e ver se o cache foi envenenado
                    resp2 = requests.get(url, timeout=5)
                    if canary in resp2.text or canary in str(resp2.headers):
                        vulns.append({
                            "tipo": "WEB_CACHE_POISONING_CONFIRMADO",
                            "pagina": page,
                            "header": header_name,
                            "severidade": "CRITICO",
                            "descricao": "Cache envenenado — refletido em requests subsequentes!",
                        })
                    else:
                        vulns.append({
                            "tipo": "WEB_CACHE_POISON_POTENCIAL",
                            "pagina": page,
                            "header": header_name,
                            "severidade": "ALTO",
                            "descricao": "Header não-keyed refletido — cache poisoning possível",
                        })

            except Exception:
                continue

    return {"plugin": "web_cache_poison", "resultados": vulns if vulns else "Nenhum cache poisoning detectado"}
