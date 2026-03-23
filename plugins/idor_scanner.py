# plugins/idor_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner IDOR (Insecure Direct Object Reference) / Broken Access Control.
    2026 Intel: OWASP 2025 A01 (Broken Access Control #1 risk),
    BOLA in APIs, predictable object references, UUID guessing,
    horizontal + vertical privilege escalation, multi-tenant bypass.
    """
    import requests

    endpoints_numeric = [
        "/api/users/{id}", "/api/v1/users/{id}", "/api/v1/user/{id}",
        "/api/orders/{id}", "/api/v1/orders/{id}", "/api/invoices/{id}",
        "/api/documents/{id}", "/api/v1/documents/{id}",
        "/api/messages/{id}", "/api/v1/messages/{id}",
        "/profile/{id}", "/user/{id}", "/account/{id}",
        "/api/v1/accounts/{id}", "/api/v1/payments/{id}",
        "/api/v1/files/{id}", "/api/v1/reports/{id}",
    ]
    test_ids = [1, 2, 3, 100, 1000, 0, -1]
    vulns = []

    for ep_template in endpoints_numeric:
        responses = {}
        for test_id in test_ids:
            ep = ep_template.replace("{id}", str(test_id))
            url = f"http://{target}{ep}"
            try:
                resp = requests.get(url, timeout=5)
                responses[test_id] = {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "has_data": any(k in resp.text.lower() for k in
                                   ["email", "name", "phone", "address", "password",
                                    "ssn", "credit", "token", "secret"]),
                }
            except Exception:
                continue

        # Analyze pattern
        success = [tid for tid, r in responses.items() if r["status"] == 200 and r["has_data"]]
        if len(success) >= 2:
            vulns.append({
                "tipo": "IDOR_BOLA", "endpoint": ep_template,
                "ids_acessiveis": success, "severidade": "CRITICO",
                "descricao": "Múltiplos IDs acessíveis sem auth — BOLA confirmado!",
            })
        elif len(success) == 1 and success[0] != 1:
            vulns.append({
                "tipo": "IDOR_POSSIVEL", "endpoint": ep_template,
                "id_acessivel": success[0], "severidade": "ALTO",
            })

        # Special IDs edge cases
        if 0 in responses and responses[0]["status"] == 200:
            vulns.append({
                "tipo": "IDOR_ZERO_ID", "endpoint": ep_template,
                "severidade": "MEDIO", "descricao": "ID=0 retorna dados — off-by-one?"
            })
        if -1 in responses and responses[-1]["status"] == 200:
            vulns.append({
                "tipo": "IDOR_NEGATIVE_ID", "endpoint": ep_template,
                "severidade": "MEDIO", "descricao": "ID negativo retorna dados — integer overflow?"
            })

    # Privilege escalation check
    priv_endpoints = [
        "/api/admin/users", "/admin/dashboard", "/api/v1/admin/config",
        "/api/v1/admin/logs", "/api/v1/admin/settings", "/api/v1/roles",
        "/api/v1/permissions", "/internal/metrics",
    ]
    for ep in priv_endpoints:
        try:
            resp = requests.get(f"http://{target}{ep}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                vulns.append({
                    "tipo": "IDOR_PRIVILEGE_ESCALATION", "endpoint": ep,
                    "severidade": "CRITICO",
                    "descricao": "Admin endpoint acessível sem autenticação!",
                })
        except Exception:
            continue

    # HTTP method override
    for ep in ["/api/users/1", "/api/v1/users/1"]:
        for method_override in ["PUT", "DELETE", "PATCH"]:
            try:
                resp = requests.request(method_override, f"http://{target}{ep}", timeout=5)
                if resp.status_code in [200, 204]:
                    vulns.append({
                        "tipo": "IDOR_METHOD_OVERRIDE", "endpoint": ep,
                        "metodo": method_override, "severidade": "CRITICO",
                        "descricao": f"{method_override} aceito sem auth — data modification!"
                    })
            except Exception:
                continue

    return {"plugin": "idor_scanner", "resultados": vulns if vulns else "Nenhum IDOR detectado"}
