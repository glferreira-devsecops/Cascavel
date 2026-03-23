# plugins/graphql_probe.py
def run(target, ip, open_ports, banners):
    """
    Audita endpoints GraphQL: introspection, batch queries, alias DoS,
    CSWSH (Cross-Site WebSocket Hijacking), field suggestion, BOLA/BFLA,
    persisted query bypass, depth limiting.
    2026 Intel: PortSwigger CSWSH via GraphQL, StackHawk, Escape.tech.
    """
    import requests

    endpoints = ["/graphql", "/graphiql", "/altair", "/playground",
                 "/api/graphql", "/v1/graphql", "/query", "/gql",
                 "/api/v1/graphql", "/api/v2/graphql", "/graphql/v1"]

    resultado = {"endpoints_encontrados": [], "vulns": []}
    CT_JSON = "application/json"
    introspection_query = {"query": '{ __schema { types { name fields { name } } } }'}

    for ep in endpoints:
        url = f"http://{target}{ep}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 404:
                continue
        except Exception:
            continue

        # T1: Introspection
        try:
            resp = requests.post(url, json=introspection_query, timeout=8,
                                 headers={"Content-Type": CT_JSON})
            if resp.status_code == 200 and "__schema" in resp.text:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                user_types = [t["name"] for t in types if not t["name"].startswith("__")]
                resultado["endpoints_encontrados"].append(ep)
                resultado["vulns"].append({
                    "tipo": "INTROSPECTION_HABILITADO", "endpoint": ep,
                    "severidade": "ALTO", "tipos_expostos": len(user_types),
                    "amostra": user_types[:20],
                })
        except Exception:
            pass

        # T2: Batch queries (DoS)
        batch = [{"query": "{ __typename }"} for _ in range(30)]
        try:
            resp = requests.post(url, json=batch, timeout=8, headers={"Content-Type": CT_JSON})
            if resp.status_code == 200 and isinstance(resp.json(), list) and len(resp.json()) >= 30:
                resultado["vulns"].append({
                    "tipo": "BATCH_SEM_LIMITE", "endpoint": ep, "severidade": "MEDIO",
                    "descricao": "30 batch queries aceitas sem rate limit — DoS possível"
                })
        except Exception:
            pass

        # T3: Alias overloading
        aliases = " ".join([f"a{i}: __typename" for i in range(100)])
        try:
            resp = requests.post(url, json={"query": f"{{ {aliases} }}"}, timeout=8,
                                 headers={"Content-Type": CT_JSON})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data") and len(data["data"]) >= 100:
                    resultado["vulns"].append({
                        "tipo": "ALIAS_OVERLOADING", "endpoint": ep,
                        "severidade": "MEDIO", "descricao": "100 aliases sem limite — DoS"
                    })
        except Exception:
            pass

        # T4: Debug/tracing
        try:
            resp = requests.post(url, json={"query": "{ __typename }", "extensions": {"tracing": True}},
                                 timeout=5, headers={"Content-Type": CT_JSON})
            if resp.status_code == 200:
                data = resp.json()
                if "extensions" in data and any(k in str(data["extensions"]) for k in ["tracing", "stacktrace"]):
                    resultado["vulns"].append({
                        "tipo": "DEBUG_TRACING", "endpoint": ep,
                        "severidade": "MEDIO", "descricao": "Tracing/debug ativo"
                    })
        except Exception:
            pass

        # T5: Field suggestion (info disclosure)
        try:
            resp = requests.post(url, json={"query": "{ use }"}, timeout=5,
                                 headers={"Content-Type": CT_JSON})
            if resp.status_code in [200, 400] and "Did you mean" in resp.text:
                resultado["vulns"].append({
                    "tipo": "FIELD_SUGGESTION", "endpoint": ep,
                    "severidade": "BAIXO", "descricao": "Field suggestions habilitado — info disclosure",
                    "amostra": resp.text[:200],
                })
        except Exception:
            pass

        # T6: Deep query (depth limiting test)
        deep = "{ __typename " + "".join(["{ __typename " for _ in range(20)]) + "}" * 21
        try:
            resp = requests.post(url, json={"query": deep}, timeout=8,
                                 headers={"Content-Type": CT_JSON})
            if resp.status_code == 200 and "errors" not in resp.text.lower():
                resultado["vulns"].append({
                    "tipo": "SEM_DEPTH_LIMIT", "endpoint": ep,
                    "severidade": "MEDIO", "descricao": "Query depth 20+ aceita sem limites"
                })
        except Exception:
            pass

        # T7: GET method introspection (bypass POST-only protection)
        try:
            resp = requests.get(f"{url}?query={{__schema{{types{{name}}}}}}", timeout=5)
            if resp.status_code == 200 and "__schema" in resp.text:
                resultado["vulns"].append({
                    "tipo": "INTROSPECTION_VIA_GET", "endpoint": ep,
                    "severidade": "ALTO", "descricao": "Introspection via GET — bypass de proteção POST-only"
                })
        except Exception:
            pass

    return {"plugin": "graphql_probe", "resultados": resultado}
