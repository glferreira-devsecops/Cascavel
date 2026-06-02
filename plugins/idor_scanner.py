# plugins/idor_scanner.py — Cascavel 2026 Intelligence
import uuid

import requests

ENDPOINTS_NUMERIC = [
    "/api/users/{id}",
    "/api/v1/users/{id}",
    "/api/v1/user/{id}",
    "/api/orders/{id}",
    "/api/v1/orders/{id}",
    "/api/invoices/{id}",
    "/api/documents/{id}",
    "/api/v1/documents/{id}",
    "/api/messages/{id}",
    "/api/v1/messages/{id}",
    "/profile/{id}",
    "/user/{id}",
    "/account/{id}",
    "/api/v1/accounts/{id}",
    "/api/v1/payments/{id}",
    "/api/v1/files/{id}",
    "/api/v1/reports/{id}",
    "/api/v2/users/{id}",
    "/api/transactions/{id}",
]

ENDPOINTS_UUID = [
    "/api/users/{uuid}",
    "/api/v1/users/{uuid}",
    "/api/documents/{uuid}",
    "/api/files/{uuid}",
    "/api/v1/orders/{uuid}",
    "/api/v1/invoices/{uuid}",
]

PII_KEYWORDS = (
    "email",
    "name",
    "phone",
    "address",
    "password",
    "ssn",
    "credit",
    "token",
    "secret",
    "salary",
    "balance",
    "account_number",
)

TEST_IDS = [1, 2, 3, 5, 10, 100, 1000, 0, -1, 999999]

TEST_UUIDS = [
    str(uuid.UUID(int=0)),  # 00000000-0000-0000-0000-000000000000
    str(uuid.UUID(int=1)),  # 00000000-0000-0000-0000-000000000001
    "a0000000-0000-0000-0000-000000000001",
]

PRIV_ENDPOINTS = [
    "/api/admin/users",
    "/admin/dashboard",
    "/api/v1/admin/config",
    "/api/v1/admin/logs",
    "/api/v1/admin/settings",
    "/api/v1/roles",
    "/api/v1/permissions",
    "/internal/metrics",
    "/admin/users",
    "/api/admin/export",
    "/api/admin/import",
    "/api/internal/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/_debug/",
    "/api/debug",
    "/server-status",
]

GRAPHQL_QUERIES = [
    '{"query":"{ users { id email name } }"}',
    '{"query":"{ user(id: 1) { id email name role } }"}',
    '{"query":"{ user(id: 2) { id email name role } }"}',
    '{"query":"{ orders { id userId amount } }"}',
    '{"query":"{ __schema { types { name fields { name } } } }"}',
]


def _get_404_baseline_len(target):
    """Obtém o tamanho do body de erro padrão para endpoints que não existem."""
    try:
        resp = requests.get(f"http://{target}/api/non_existent_endpoint_12345", timeout=5)
        return len(resp.text)
    except Exception:
        return 0


def _probe_endpoint(target, ep_template, id_list):
    """Testa um endpoint IDOR com múltiplos IDs."""
    responses = {}
    for test_id in id_list:
        ep = ep_template.replace("{id}", str(test_id)).replace("{uuid}", str(test_id))
        url = f"http://{target}{ep}"
        try:
            resp = requests.get(url, timeout=5)
            has_data = any(k in resp.text.lower() for k in PII_KEYWORDS)
            responses[test_id] = {
                "status": resp.status_code,
                "length": len(resp.text),
                "has_data": has_data,
            }
        except Exception:
            continue
    return responses


def _analyze_responses(responses, ep_template, baseline_len):
    """Analisa padrões de resposta para detectar IDOR/BOLA com diff checking rigoroso."""
    vulns = []
    success = [tid for tid, r in responses.items() if r["status"] == 200 and r["has_data"]]
    success_200 = [tid for tid, r in responses.items() if r["status"] == 200]

    # Verifica se os sucessos não são apenas soft-404 refletindo ID ou body genérico
    valid_success = []
    for tid in success:
        diff_len = abs(responses[tid]["length"] - baseline_len)
        if baseline_len == 0 or diff_len > (baseline_len * 0.05):
            valid_success.append(tid)

    if len(valid_success) >= 2:
        vulns.append(
            {
                "tipo": "IDOR_BOLA",
                "endpoint": ep_template,
                "ids_acessiveis": valid_success[:5],
                "severidade": "CRITICO",
                "descricao": "Múltiplos IDs com PII acessíveis sem auth — BOLA confirmado via Response Diffing!",
            }
        )
    elif len(success_200) >= 3:
        # Different lengths suggest different users' data, tolerância de 5% p/ falsos positivos
        lengths = set(responses[tid]["length"] for tid in success_200)
        max_len = max(lengths) if lengths else 0
        min_len = min(lengths) if lengths else 0
        if max_len > 0 and abs(max_len - min_len) > (max_len * 0.05):
            vulns.append(
                {
                    "tipo": "IDOR_POSSIVEL",
                    "endpoint": ep_template,
                    "ids_200": success_200[:5],
                    "severidade": "ALTO",
                    "descricao": "Múltiplos IDs retornam respostas sensivelmente diferentes — provável IDOR!",
                }
            )

    if (
        0 in responses
        and responses[0]["status"] == 200
        and abs(responses[0]["length"] - baseline_len) > (baseline_len * 0.05)
    ):
        vulns.append(
            {
                "tipo": "IDOR_ZERO_ID",
                "endpoint": ep_template,
                "severidade": "MEDIO",
                "descricao": "ID=0 retorna dados válidos — off-by-one!",
            }
        )
    if (
        -1 in responses
        and responses[-1]["status"] == 200
        and abs(responses[-1]["length"] - baseline_len) > (baseline_len * 0.05)
    ):
        vulns.append(
            {
                "tipo": "IDOR_NEGATIVE_ID",
                "endpoint": ep_template,
                "severidade": "MEDIO",
                "descricao": "ID negativo retorna dados válidos — integer overflow?",
            }
        )
    if (
        999999 in responses
        and responses[999999]["status"] == 200
        and abs(responses[999999]["length"] - baseline_len) > (baseline_len * 0.05)
    ):
        vulns.append(
            {
                "tipo": "IDOR_LARGE_ID",
                "endpoint": ep_template,
                "severidade": "MEDIO",
                "descricao": "ID gigante retorna dados válidos — enumeration bypass!",
            }
        )

    return vulns


def _check_privilege_escalation(target):
    """Verifica endpoints administrativos acessíveis sem autenticação."""
    vulns = []
    for ep in PRIV_ENDPOINTS:
        try:
            resp = requests.get(f"http://{target}{ep}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                vulns.append(
                    {
                        "tipo": "IDOR_PRIVILEGE_ESCALATION",
                        "endpoint": ep,
                        "severidade": "CRITICO",
                        "descricao": f"Admin endpoint '{ep}' acessível sem autenticação!",
                    }
                )
        except Exception:
            continue
    return vulns


def _check_method_override(target):
    """Testa HTTP method override (PUT/DELETE/PATCH) sem autenticação."""
    vulns = []
    for ep in ["/api/users/1", "/api/v1/users/1", "/api/v1/accounts/1"]:
        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                resp = requests.request(method, f"http://{target}{ep}", timeout=5, json={"role": "admin"})
                if resp.status_code in (200, 204):
                    vulns.append(
                        {
                            "tipo": "IDOR_METHOD_OVERRIDE",
                            "endpoint": ep,
                            "metodo": method,
                            "severidade": "CRITICO",
                            "descricao": f"{method} aceito sem auth — data modification!",
                        }
                    )
            except Exception:
                continue
    return vulns


def _check_graphql_idor(target):
    """Testa IDOR via GraphQL queries."""
    vulns = []
    for gql_ep in ["/graphql", "/api/graphql", "/api/v1/graphql"]:
        for query in GRAPHQL_QUERIES:
            try:
                resp = requests.post(
                    f"http://{target}{gql_ep}",
                    data=query,
                    timeout=5,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200 and any(k in resp.text.lower() for k in PII_KEYWORDS):
                    vulns.append(
                        {
                            "tipo": "IDOR_GRAPHQL",
                            "endpoint": gql_ep,
                            "severidade": "CRITICO",
                            "descricao": "GraphQL query retorna PII sem auth — BOLA via GraphQL!",
                            "amostra": resp.text[:200],
                        }
                    )
                    return vulns  # One is enough
            except Exception:
                continue
    return vulns


def _check_parameter_pollution(target):
    """Testa IDOR via HTTP Parameter Pollution."""
    vulns = []
    hpp_urls = [
        "/api/users?id=1&id=2",
        "/api/v1/profile?user_id=1&user_id=2",
        "/api/account?id=1&id=admin",
    ]
    for url_path in hpp_urls:
        try:
            resp = requests.get(f"http://{target}{url_path}", timeout=5)
            if resp.status_code == 200 and any(k in resp.text.lower() for k in PII_KEYWORDS):
                vulns.append(
                    {
                        "tipo": "IDOR_HPP",
                        "path": url_path,
                        "severidade": "ALTO",
                        "descricao": "HTTP Parameter Pollution retorna dados extras — IDOR!",
                    }
                )
        except Exception:
            continue
    return vulns


def _check_uuid_prediction(target, baseline_len):
    """Testa IDOR com UUIDs previsíveis (v1 timestamp-based)."""
    vulns = []
    for ep_template in ENDPOINTS_UUID:
        responses = _probe_endpoint(target, ep_template, TEST_UUIDS)
        success = [
            uid
            for uid, r in responses.items()
            if r["status"] == 200 and r.get("has_data") and abs(r["length"] - baseline_len) > (baseline_len * 0.05)
        ]
        if success:
            vulns.append(
                {
                    "tipo": "IDOR_UUID_PREDICTABLE",
                    "endpoint": ep_template,
                    "uuids_acessiveis": success,
                    "severidade": "ALTO",
                    "descricao": "UUIDs sequenciais/previsíveis retornam dados sensíveis validados — IDOR!",
                }
            )
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner IDOR 2026-Grade — BOLA/BFLA, GraphQL, UUID, HPP, Privilege Escalation.

    Técnicas: 19 numeric endpoint patterns, UUID prediction (v1 timestamp),
    GraphQL node enumeration, HTTP Parameter Pollution, 18 admin endpoints,
    method override (PUT/DELETE/PATCH), zero/negative/large ID probing,
    PII keyword detection, actuator/debug endpoint exposure.
    OWASP 2025 A01 (Broken Access Control).
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # Obtem baseline para ignorar Soft-404s ou pages padrao WAF
    baseline_len = _get_404_baseline_len(target)

    # 1. Numeric IDOR
    for ep_template in ENDPOINTS_NUMERIC:
        responses = _probe_endpoint(target, ep_template, TEST_IDS)
        vulns.extend(_analyze_responses(responses, ep_template, baseline_len))

    # 2. UUID IDOR
    vulns.extend(_check_uuid_prediction(target, baseline_len))

    # 3. Privilege escalation
    vulns.extend(_check_privilege_escalation(target))

    # 4. Method override
    vulns.extend(_check_method_override(target))

    # 5. GraphQL IDOR
    vulns.extend(_check_graphql_idor(target))

    # 6. Parameter pollution
    vulns.extend(_check_parameter_pollution(target))

    return {
        "plugin": "idor_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "bola",
            "bfla",
            "uuid_prediction",
            "graphql_idor",
            "method_override",
            "hpp",
            "privilege_escalation",
            "actuator_exposure",
        ],
        "resultados": vulns if vulns else "Nenhum IDOR detectado",
    }
