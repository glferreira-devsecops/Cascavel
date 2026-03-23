# plugins/idor_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner IDOR (Insecure Direct Object Reference).
    Testa manipulação de IDs sequenciais em endpoints de API comuns.
    OWASP A01:2021 — Broken Access Control.
    """
    import requests

    api_patterns = [
        "/api/users/{id}", "/api/user/{id}", "/api/v1/users/{id}",
        "/api/profile/{id}", "/api/account/{id}", "/api/v1/account/{id}",
        "/api/orders/{id}", "/api/v1/orders/{id}",
        "/api/invoices/{id}", "/api/documents/{id}",
        "/user/{id}", "/profile/{id}", "/account/{id}",
        "/admin/users/{id}", "/api/admin/users/{id}",
    ]

    test_ids = [1, 2, 3, 100, 1000, 0, -1]
    vulns = []

    for pattern in api_patterns:
        resultados_por_id = {}
        for test_id in test_ids:
            path = pattern.replace("{id}", str(test_id))
            url = f"http://{target}{path}"
            try:
                resp = requests.get(url, timeout=5)
                resultados_por_id[test_id] = {
                    "status": resp.status_code,
                    "tamanho": len(resp.text),
                    "content_type": resp.headers.get("Content-Type", ""),
                }

                # Detecção direta: retorna dados JSON com ID diferente
                if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                    try:
                        data = resp.json()
                        # Verificar se retorna dados de outro usuário
                        if isinstance(data, dict) and any(k in data for k in
                                                          ["email", "username", "name", "phone", "address",
                                                           "password", "ssn", "credit_card"]):
                            vuln = {
                                "tipo": "IDOR",
                                "endpoint": pattern,
                                "id_testado": test_id,
                                "severidade": "CRITICO",
                                "campos_expostos": [k for k in data.keys()
                                                    if k in ["email", "username", "name", "phone",
                                                             "address", "password", "ssn", "credit_card"]],
                            }
                            if "password" in data or "ssn" in data or "credit_card" in data:
                                vuln["descricao"] = "DADOS SENSÍVEIS EXPOSTOS via IDOR!"
                            vulns.append(vuln)
                    except Exception:
                        pass
            except Exception:
                continue

        # Análise heurística: múltiplos IDs retornam 200 com tamanhos diferentes
        ok_responses = {k: v for k, v in resultados_por_id.items()
                        if v["status"] == 200 and v["tamanho"] > 50}
        if len(ok_responses) >= 2:
            tamanhos = set(v["tamanho"] for v in ok_responses.values())
            if len(tamanhos) >= 2:  # Diferentes tamanhos = dados diferentes
                vulns.append({
                    "tipo": "IDOR_PROVAVEL",
                    "endpoint": pattern,
                    "severidade": "ALTO",
                    "ids_acessiveis": list(ok_responses.keys()),
                    "descricao": "Múltiplos IDs retornam 200 com dados diferentes — possível IDOR"
                })

    return {
        "plugin": "idor_scanner",
        "resultados": vulns if vulns else "Nenhum IDOR detectado nos endpoints testados"
    }
