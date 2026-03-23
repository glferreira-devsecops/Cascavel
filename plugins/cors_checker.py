# plugins/cors_checker.py
def run(target, ip, open_ports, banners):
    """
    Verifica misconfigurações CORS (Cross-Origin Resource Sharing).
    Testa origins maliciosos para identificar permissões excessivas.
    """
    import requests

    test_origins = [
        "https://evil.com",
        f"https://{target}.evil.com",
        "null",
        f"https://sub.{target}",
        "https://attacker.io",
        f"http://{target}",  # HTTP no lugar de HTTPS
    ]
    vulns = []

    for origin in test_origins:
        headers_req = {"Origin": origin}
        try:
            resp = requests.get(f"http://{target}", headers=headers_req, timeout=6)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            creds = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                vuln = {
                    "origin_testado": origin,
                    "acao_retornado": acao,
                    "credentials": creds,
                    "severidade": "INFO",
                }

                # Classificar severidade
                if acao == "*":
                    vuln["severidade"] = "MEDIO"
                    vuln["descricao"] = "Wildcard CORS — qualquer origin aceito"
                elif acao == origin and "evil" in origin:
                    vuln["severidade"] = "CRITICO"
                    vuln["descricao"] = "Origin malicioso refletido!"
                elif acao == "null":
                    vuln["severidade"] = "ALTO"
                    vuln["descricao"] = "CORS aceita origin 'null' (sandbox bypass)"
                elif creds.lower() == "true" and acao == origin:
                    vuln["severidade"] = "CRITICO"
                    vuln["descricao"] = "Origin refletido COM credentials — full takeover possível"

                if vuln["severidade"] != "INFO":
                    vulns.append(vuln)
        except Exception:
            continue

    # Testar também a API (se existir)
    for api_path in ["/api/", "/api/v1/", "/graphql"]:
        for origin in ["https://evil.com"]:
            try:
                resp = requests.get(f"http://{target}{api_path}", headers={"Origin": origin}, timeout=4)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin:
                    vulns.append({
                        "endpoint": api_path,
                        "origin_testado": origin,
                        "acao_retornado": acao,
                        "severidade": "CRITICO",
                        "descricao": "API endpoint com CORS misconfiguration",
                    })
            except Exception:
                continue

    return {
        "plugin": "cors_checker",
        "resultados": vulns if vulns else "CORS configurado corretamente ou não presente"
    }
