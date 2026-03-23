# plugins/graphql_probe.py
def run(target, ip, open_ports, banners):
    """
    Audita endpoints GraphQL: introspection, batch queries, alias DoS.
    Baseado em GraphQL Cop + melhores práticas 2026.
    """
    import requests
    import json

    endpoints = ["/graphql", "/graphiql", "/altair", "/playground",
                 "/api/graphql", "/v1/graphql", "/query", "/gql"]

    resultado = {"endpoints_encontrados": [], "vulns": []}

    introspection_query = {
        "query": '{ __schema { types { name fields { name } } } }'
    }

    for ep in endpoints:
        url = f"http://{target}{ep}"

        # 1. Verificar existência do endpoint
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in [400, 405]:
                # GraphQL pode retornar 400 em GET sem query
                pass
            elif resp.status_code == 404:
                continue
        except Exception:
            continue

        # 2. Testar introspection
        try:
            resp = requests.post(url, json=introspection_query, timeout=8,
                                 headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if "__schema" in str(data) or "types" in str(data):
                    resultado["endpoints_encontrados"].append(ep)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    user_types = [t["name"] for t in types
                                  if not t["name"].startswith("__")]
                    resultado["vulns"].append({
                        "tipo": "INTROSPECTION_HABILITADO",
                        "endpoint": ep,
                        "severidade": "ALTO",
                        "tipos_expostos": len(user_types),
                        "amostra_tipos": user_types[:15],
                        "descricao": "Schema completo exposto via introspection"
                    })
        except Exception:
            pass

        # 3. Testar batch queries (DoS)
        batch_payload = [{"query": "{ __typename }"} for _ in range(25)]
        try:
            resp = requests.post(url, json=batch_payload, timeout=8,
                                 headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 25:
                    resultado["vulns"].append({
                        "tipo": "BATCH_QUERIES_SEM_LIMITE",
                        "endpoint": ep,
                        "severidade": "MEDIO",
                        "descricao": "Batch queries aceitas sem limite — risco de DoS"
                    })
        except Exception:
            pass

        # 4. Testar alias overloading
        aliases = " ".join([f"a{i}: __typename" for i in range(100)])
        alias_payload = {"query": f"{{ {aliases} }}"}
        try:
            resp = requests.post(url, json=alias_payload, timeout=8,
                                 headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data") and len(data["data"]) >= 100:
                    resultado["vulns"].append({
                        "tipo": "ALIAS_OVERLOADING",
                        "endpoint": ep,
                        "severidade": "MEDIO",
                        "descricao": "100 aliases processados sem limite — risco de DoS"
                    })
        except Exception:
            pass

        # 5. Verificar debug/tracing
        debug_payload = {"query": "{ __typename }", "extensions": {"tracing": True}}
        try:
            resp = requests.post(url, json=debug_payload, timeout=5,
                                 headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                if "extensions" in data and ("tracing" in str(data["extensions"]) or
                                              "stacktrace" in str(data)):
                    resultado["vulns"].append({
                        "tipo": "DEBUG_TRACING_HABILITADO",
                        "endpoint": ep,
                        "severidade": "MEDIO",
                        "descricao": "Tracing/debug ativo — information disclosure"
                    })
        except Exception:
            pass

    return {"plugin": "graphql_probe", "resultados": resultado}
