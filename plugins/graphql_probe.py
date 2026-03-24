# plugins/graphql_probe.py — Cascavel 2026 Intelligence
import requests
import json


CT_JSON = "application/json"
INTROSPECTION_QUERY = {"query": "{ __schema { types { name fields { name type { name } } } } }"}

ENDPOINTS = [
    "/graphql", "/graphiql", "/altair", "/playground",
    "/api/graphql", "/v1/graphql", "/query", "/gql",
    "/api/v1/graphql", "/api/v2/graphql", "/graphql/v1",
    "/api/internal/graphql", "/graphql/console",
]


def run(target, ip, open_ports, banners):
    """
    Auditor GraphQL 2026-Grade — Introspection, Batch, Alias, CSWSH.

    Técnicas: Introspection (POST/GET), batch query DoS (30+),
    alias overloading (100), deep query (depth 20+),
    field suggestion info disclosure, debug/tracing mode,
    GET introspection bypass, persisted query bypass,
    CSWSH via WebSocket, cost analysis detection.
    """
    _ = (ip, open_ports, banners)
    resultado = {"endpoints_encontrados": [], "vulns": []}

    for ep in ENDPOINTS:
        url = f"http://{target}{ep}"
        try:
            resp = requests.post(url, json={"query": "{ __typename }"},
                                 headers={"Content-Type": CT_JSON}, timeout=5)
            if resp.status_code == 404:
                continue
            if resp.status_code != 200 and "graphql" not in resp.text.lower():
                continue
        except Exception:
            continue

        resultado["endpoints_encontrados"].append(ep)
        _test_introspection(url, ep, resultado)
        _test_batch(url, ep, resultado)
        _test_alias(url, ep, resultado)
        _test_debug(url, ep, resultado)
        _test_field_suggestion(url, ep, resultado)
        _test_depth(url, ep, resultado)
        _test_get_introspection(url, ep, resultado)
        _test_persisted_query_bypass(url, ep, resultado)
        _test_cswsh(target, ep, resultado)
        _test_cost_analysis(url, ep, resultado)

    return {"plugin": "graphql_probe", "versao": "2026.1", "resultados": resultado}


def _test_introspection(url, ep, resultado):
    try:
        resp = requests.post(url, json=INTROSPECTION_QUERY, timeout=8,
                             headers={"Content-Type": CT_JSON})
        if resp.status_code == 200 and "__schema" in resp.text:
            data = resp.json()
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            user_types = [t["name"] for t in types if not t["name"].startswith("__")]
            resultado["vulns"].append({
                "tipo": "INTROSPECTION_HABILITADO", "endpoint": ep,
                "severidade": "ALTO", "tipos_expostos": len(user_types),
                "amostra": user_types[:20],
            })
    except Exception:
        pass


def _test_batch(url, ep, resultado):
    batch = [{"query": "{ __typename }"} for _ in range(30)]
    try:
        resp = requests.post(url, json=batch, timeout=8,
                             headers={"Content-Type": CT_JSON})
        if resp.status_code == 200 and isinstance(resp.json(), list) and len(resp.json()) >= 30:
            resultado["vulns"].append({
                "tipo": "BATCH_SEM_LIMITE", "endpoint": ep, "severidade": "MEDIO",
                "descricao": "30 batch queries aceitas sem rate limit — DoS possível!",
            })
    except Exception:
        pass


def _test_alias(url, ep, resultado):
    aliases = " ".join([f"a{i}: __typename" for i in range(100)])
    try:
        resp = requests.post(url, json={"query": f"{{ {aliases} }}"},
                             timeout=8, headers={"Content-Type": CT_JSON})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and len(data["data"]) >= 100:
                resultado["vulns"].append({
                    "tipo": "ALIAS_OVERLOADING", "endpoint": ep,
                    "severidade": "MEDIO", "descricao": "100 aliases aceitos — DoS via alias overloading!",
                })
    except Exception:
        pass


def _test_debug(url, ep, resultado):
    try:
        resp = requests.post(
            url, json={"query": "{ __typename }", "extensions": {"tracing": True}},
            timeout=5, headers={"Content-Type": CT_JSON},
        )
        if resp.status_code == 200:
            data = resp.json()
            if "extensions" in data and any(k in str(data["extensions"])
                                             for k in ["tracing", "stacktrace", "resolvers"]):
                resultado["vulns"].append({
                    "tipo": "DEBUG_TRACING", "endpoint": ep,
                    "severidade": "MEDIO", "descricao": "Tracing/debug ativo — info disclosure!",
                })
    except Exception:
        pass


def _test_field_suggestion(url, ep, resultado):
    try:
        resp = requests.post(url, json={"query": "{ use }"},
                             timeout=5, headers={"Content-Type": CT_JSON})
        if resp.status_code in [200, 400] and "Did you mean" in resp.text:
            resultado["vulns"].append({
                "tipo": "FIELD_SUGGESTION", "endpoint": ep,
                "severidade": "BAIXO", "descricao": "Field suggestions expostas — schema enumeration!",
                "amostra": resp.text[:200],
            })
    except Exception:
        pass


def _test_depth(url, ep, resultado):
    deep = "{ __typename " + "".join(["{ __typename " for _ in range(20)]) + "}" * 21
    try:
        resp = requests.post(url, json={"query": deep}, timeout=8,
                             headers={"Content-Type": CT_JSON})
        if resp.status_code == 200 and "errors" not in resp.text.lower():
            resultado["vulns"].append({
                "tipo": "SEM_DEPTH_LIMIT", "endpoint": ep,
                "severidade": "MEDIO", "descricao": "Query depth 20+ aceita — DoS potencial!",
            })
    except Exception:
        pass


def _test_get_introspection(url, ep, resultado):
    try:
        resp = requests.get(f"{url}?query={{__schema{{types{{name}}}}}}", timeout=5)
        if resp.status_code == 200 and "__schema" in resp.text:
            resultado["vulns"].append({
                "tipo": "INTROSPECTION_VIA_GET", "endpoint": ep,
                "severidade": "ALTO", "descricao": "Introspection via GET — bypass de proteção POST-only!",
            })
    except Exception:
        pass


def _test_persisted_query_bypass(url, ep, resultado):
    """Testa bypass de persisted queries via APQ hash."""
    try:
        resp = requests.post(url, json={
            "extensions": {"persistedQuery": {
                "version": 1, "sha256Hash": "0" * 64,
            }},
        }, timeout=5, headers={"Content-Type": CT_JSON})
        if resp.status_code == 200 and "PersistedQueryNotFound" in resp.text:
            resultado["vulns"].append({
                "tipo": "APQ_ENABLED", "endpoint": ep,
                "severidade": "BAIXO",
                "descricao": "Automatic Persisted Queries habilitado — hash enumeration possível!",
            })
    except Exception:
        pass


def _test_cswsh(target, ep, resultado):
    """Testa CSWSH (Cross-Site WebSocket Hijacking) via GraphQL subscriptions."""
    try:
        resp = requests.get(f"http://{target}{ep}",
                            headers={"Upgrade": "websocket", "Connection": "Upgrade",
                                     "Origin": "https://evil.com"},
                            timeout=5)
        if resp.status_code == 101 or "upgrade" in resp.headers.get("Connection", "").lower():
            resultado["vulns"].append({
                "tipo": "CSWSH_GRAPHQL", "endpoint": ep,
                "severidade": "ALTO",
                "descricao": "WebSocket upgrade aceita com evil origin — CSWSH!",
            })
    except Exception:
        pass


def _test_cost_analysis(url, ep, resultado):
    """Testa se cost analysis/complexity limit existe."""
    expensive = "{ users { friends { friends { friends { name email } } } } }"
    try:
        resp = requests.post(url, json={"query": expensive},
                             timeout=8, headers={"Content-Type": CT_JSON})
        if resp.status_code == 200 and "cost" not in resp.text.lower() and "complexity" not in resp.text.lower():
            if "errors" not in resp.text.lower():
                resultado["vulns"].append({
                    "tipo": "SEM_COST_ANALYSIS", "endpoint": ep,
                    "severidade": "MEDIO",
                    "descricao": "Query complexa aceita sem cost/complexity analysis — DoS!",
                })
    except Exception:
        pass
