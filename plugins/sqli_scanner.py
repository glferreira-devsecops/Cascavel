# plugins/sqli_scanner.py
def run(target, results):
    """
    Scanner básico de SQLi por GET. 
    Envia payloads clássicos e detecta possíveis vulnerabilidades por padrões na resposta.
    """
    import requests
    payloads = [
        "1'", "1''", "1 or 1=1--", "' OR '1'='1", "1) or (1=1--", "\" OR \"1\"=\"1", "admin'--", "admin' #"
    ]
    palavras_chave = ["mysql", "syntax", "sql", "warning", "ora-", "sqlite", "error", "unexpected", "you have an error"]
    vulns = []

    for payload in payloads:
        url = f"http://{target}/?id={payload}"
        try:
            resp = requests.get(url, timeout=8)
            lower = resp.text.lower()
            if any(chave in lower for chave in palavras_chave):
                vulns.append({
                    "payload": payload,
                    "codigo_http": resp.status_code,
                    "indicador": [k for k in palavras_chave if k in lower],
                    "amostra_resposta": resp.text[:300]
                })
        except requests.Timeout:
            continue
        except Exception as e:
            vulns.append({"payload": payload, "erro": str(e)})

    results['sqli_scan'] = vulns if vulns else "Nenhuma vulnerabilidade SQLi clássica detectada"
