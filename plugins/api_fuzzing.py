# plugins/api_fuzzing.py — Cascavel 2026 Intelligence
import json

import requests

# REST API discovery paths
REST_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/info",
    "/api/v2/users",
    "/api/v2/admin",
    "/api/v2/config",
    "/api/internal",
    "/api/private",
    "/api/public",
    "/api/legacy",
    "/api/beta",
    "/api/alpha",
    "/v1",
    "/v2",
    "/v3",
    "/v4",
    "/rest",
    "/rest/api",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/gql",
    "/graphiql",
    "/grpc",
    "/rpc",
    "/jsonrpc",
]

# GraphQL introspection query
INTROSPECTION_QUERY = {
    "query": """
    {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind }
                }
            }
        }
    }
    """
}

# GraphQL test queries
GRAPHQL_TESTS = [
    ("{ __typename }", "typename"),
    ('query { __type(name: "Query") { fields { name } } }', "type_fields"),
    ("{ users { id email password } }", "sensitive_fields"),
    ("mutation { deleteUser(id: 1) }", "mutation_test"),
    ("{ admin { config } }", "admin_probe"),
]

# gRPC service paths
GRPC_PATHS = [
    "/grpc",
    "/grpc.reflection.v1alpha.ServerReflection",
    "/grpc.health.v1.Health",
    "/grpc-web",
    "/api/grpc",
    "/rpc/grpc",
]

# Auth bypass techniques
AUTH_BYPASS = [
    ({"Authorization": "Bearer null"}, "null_token"),
    ({"Authorization": "Bearer undefined"}, "undefined_token"),
    ({"Authorization": "Bearer admin"}, "admin_token"),
    ({"Authorization": "Bearer test"}, "test_token"),
    ({"Authorization": "Bearer <NONE_ALG_JWT_PLACEHOLDER>"}, "none_alg_jwt"),
    ({"X-Api-Key": "admin"}, "admin_api_key"),
    ({"X-Api-Key": "test"}, "test_api_key"),
    ({"X-Forwarded-For": "127.0.0.1"}, "ip_spoof"),
    ({"X-Original-URL": "/admin"}, "url_override"),
    ({"X-Rewrite-URL": "/admin"}, "url_rewrite"),
    ({"X-Custom-IP-Authorization": "127.0.0.1"}, "custom_ip_auth"),
]

# Mass assignment test payloads
MASS_ASSIGNMENT_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"permissions": ["admin", "superuser"]},
    {"user_type": "admin"},
    {"access_level": 999},
    {"is_superuser": True},
    {"role_id": 1},
    {"group": "administrators"},
]


def _discover_rest_endpoints(target):
    """Discover REST API endpoints."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    for path in REST_PATHS:
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(f"{scheme}://{clean}{path}", timeout=5, verify=False)
                if resp.status_code in [200, 201, 204, 301, 302, 401, 403, 405]:
                    finding = {
                        "tipo": "API_ENDPOINT",
                        "path": path,
                        "status": resp.status_code,
                        "scheme": scheme,
                        "severidade": "INFO",
                    }

                    # Classify based on response
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        try:
                            data = resp.json()
                            finding["tipo_resposta"] = "JSON"
                            if isinstance(data, list):
                                finding["quantidade_items"] = len(data)
                            elif isinstance(data, dict):
                                finding["chaves"] = list(data.keys())[:10]
                        except Exception:
                            finding["tipo_resposta"] = "TEXT"

                        if any(kw in body for kw in ["admin", "config", "internal", "debug"]):
                            finding["severidade"] = "ALTO"
                    elif resp.status_code == 401:
                        finding["severidade"] = "MEDIO"
                        finding["descricao"] = "Endpoint requer autenticação"
                    elif resp.status_code == 403:
                        finding["severidade"] = "MEDIO"
                        finding["descricao"] = "Endpoint existe mas acesso negado"
                    elif resp.status_code == 405:
                        finding["severidade"] = "INFO"
                        finding["descricao"] = "Endpoint existe mas método não permitido"

                    # Check response headers for API info
                    if "X-API-Version" in resp.headers:
                        finding["api_version"] = resp.headers["X-API-Version"]
                    if "X-RateLimit-Limit" in resp.headers:
                        finding["rate_limit"] = resp.headers["X-RateLimit-Limit"]

                    findings.append(finding)
                    break  # Found on one scheme, skip the other
            except Exception:
                continue

    return findings


def _test_graphql_introspection(target):
    """Test GraphQL introspection."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    graphql_paths = ["/graphql", "/gql", "/graphiql", "/api/graphql", "/v1/graphql"]

    for path in graphql_paths:
        for scheme in ["https", "http"]:
            try:
                # Try introspection
                resp = requests.post(
                    f"{scheme}://{clean}{path}",
                    json=INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    verify=False,
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and "__schema" in data.get("data", {}):
                            schema = data["data"]["__schema"]
                            types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
                            queries = schema.get("queryType", {}).get("name", "")
                            mutations = schema.get("mutationType", {}).get("name", "")

                            findings.append(
                                {
                                    "tipo": "GRAPHQL_INTROSPECTION",
                                    "path": path,
                                    "scheme": scheme,
                                    "queries": queries,
                                    "mutations": mutations,
                                    "total_types": len(types),
                                    "types_amostra": types[:20],
                                    "severidade": "CRITICO",
                                    "descricao": f"GraphQL introspection habilitada — {len(types)} types expostos, mutations disponíveis",
                                    "remediacao": "Desabilitar introspection em produção. Implementar persisted queries.",
                                }
                            )
                        elif "data" in data:
                            findings.append(
                                {
                                    "tipo": "GRAPHQL_ACTIVE",
                                    "path": path,
                                    "scheme": scheme,
                                    "severidade": "ALTO",
                                    "descricao": "GraphQL endpoint ativo mas introspection desabilitada",
                                    "remediacao": "Manter introspection desabilitada. Validar queries com whitelist.",
                                }
                            )
                    except json.JSONDecodeError:
                        pass
                    break
            except Exception:
                continue

    # Test other GraphQL queries
    for path in ["/graphql"]:
        for scheme in ["https", "http"]:
            for query, label in GRAPHQL_TESTS:
                try:
                    resp = requests.post(
                        f"{scheme}://{clean}{path}",
                        json={"query": query},
                        headers={"Content-Type": "application/json"},
                        timeout=5,
                        verify=False,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if "errors" not in data or (isinstance(data.get("errors"), list) and len(data["errors"]) == 0):
                            findings.append(
                                {
                                    "tipo": "GRAPHQL_QUERY_SUCCESS",
                                    "query_label": label,
                                    "query": query[:100],
                                    "severidade": "ALTO" if "admin" in label or "sensitive" in label else "MEDIO",
                                    "descricao": f"GraphQL query '{label}' retornou dados",
                                    "remediacao": "Implementar query depth limiting. Restringir campos sensíveis.",
                                }
                            )
                except Exception:
                    continue
            break

    return findings


def _test_grpc_enumeration(target):
    """Test gRPC service enumeration."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    for path in GRPC_PATHS:
        for scheme in ["https", "http"]:
            try:
                # Try gRPC reflection
                resp = requests.post(
                    f"{scheme}://{clean}{path}",
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                    },
                    timeout=5,
                    verify=False,
                )
                if resp.status_code in [200, 415]:
                    finding = {
                        "tipo": "GRPC_ENDPOINT",
                        "path": path,
                        "status": resp.status_code,
                        "severidade": "ALTO",
                        "descricao": f"gRPC endpoint ativo em {path}",
                        "remediacao": "Desabilitar gRPC reflection em produção. Implementar autenticação mTLS.",
                    }

                    # Check for health check
                    if "health" in path:
                        try:
                            health_resp = requests.get(
                                f"{scheme}://{clean}{path}",
                                timeout=5,
                                verify=False,
                            )
                            if health_resp.status_code == 200:
                                finding["health_check"] = True
                                finding["severidade"] = "MEDIO"
                        except Exception as _exc:
                            pass

                    findings.append(finding)
            except Exception:
                continue

    return findings


def _test_auth_bypass(target):
    """Test API authentication bypass."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Find protected endpoints first
    protected_paths = []
    for path in ["/api/v1/admin", "/api/v1/users", "/api/admin", "/admin", "/api/internal"]:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 401:
                protected_paths.append(path)
        except Exception:
            continue

    if not protected_paths:
        return findings

    # Test bypass techniques on first protected endpoint
    target_path = protected_paths[0]
    for headers, technique in AUTH_BYPASS:
        try:
            resp = requests.get(
                f"https://{clean}{target_path}",
                headers=headers,
                timeout=5,
                verify=False,
            )
            if resp.status_code == 200:
                findings.append(
                    {
                        "tipo": "AUTH_BYPASS",
                        "tecnica": technique,
                        "path": target_path,
                        "headers": headers,
                        "severidade": "CRITICO",
                        "descricao": f"Bypass de autenticação via {technique} em {target_path}",
                        "remediacao": "Validar tokens server-side. Não confiar em headers customizados para autorização.",
                    }
                )
        except Exception:
            continue

    return findings


def _test_rate_limiting(target):
    """Test API rate limiting."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Test rate limiting on API endpoints
    test_paths = ["/api", "/api/v1", "/login", "/api/v1/auth"]
    for path in test_paths:
        try:
            responses = []
            for _i in range(20):  # Send 20 rapid requests
                resp = requests.get(f"https://{clean}{path}", timeout=3, verify=False)
                responses.append(resp.status_code)
                if resp.status_code == 429:
                    break

            if 429 not in responses:
                findings.append(
                    {
                        "tipo": "NO_RATE_LIMITING",
                        "path": path,
                        "requests_sent": len(responses),
                        "severidade": "ALTO",
                        "descricao": f"Sem rate limiting em {path} — {len(responses)} requests sem bloqueio",
                        "remediacao": "Implementar rate limiting (ex: 100 req/min por IP). Usar API gateway.",
                    }
                )
            else:
                limit_index = responses.index(429)
                findings.append(
                    {
                        "tipo": "RATE_LIMIT_ACTIVE",
                        "path": path,
                        "requests_ate_bloqueio": limit_index + 1,
                        "severidade": "INFO",
                        "descricao": f"Rate limiting ativo em {path} — bloqueio após {limit_index + 1} requests",
                    }
                )
            break  # Test one path only
        except Exception:
            continue

    return findings


def _test_mass_assignment(target):
    """Test for mass assignment vulnerabilities."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Find endpoints that accept POST/PUT
    test_paths = ["/api/v1/users", "/api/users", "/api/v1/profile", "/api/profile"]
    for path in test_paths:
        # First check if endpoint exists
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code not in [200, 401, 403, 405]:
                continue

            # Test mass assignment
            for payload in MASS_ASSIGNMENT_PAYLOADS:
                for method in ["POST", "PUT", "PATCH"]:
                    try:
                        if method == "POST":
                            resp = requests.post(
                                f"https://{clean}{path}",
                                json=payload,
                                timeout=5,
                                verify=False,
                            )
                        elif method == "PUT":
                            resp = requests.put(
                                f"https://{clean}{path}",
                                json=payload,
                                timeout=5,
                                verify=False,
                            )
                        else:
                            resp = requests.patch(
                                f"https://{clean}{path}",
                                json=payload,
                                timeout=5,
                                verify=False,
                            )

                        if resp.status_code in [200, 201]:
                            try:
                                data = resp.json()
                                # Check if our injected field appears in response
                                for key in payload:
                                    if key in str(data).lower():
                                        findings.append(
                                            {
                                                "tipo": "MASS_ASSIGNMENT",
                                                "path": path,
                                                "method": method,
                                                "payload": payload,
                                                "campo_aceito": key,
                                                "severidade": "CRITICO",
                                                "descricao": f"Mass assignment via {method} — campo '{key}' aceito em {path}",
                                                "remediacao": "Usar DTOs/serializers com whitelist de campos. Nunca bindar input diretamente em models.",
                                            }
                                        )
                                        break
                            except Exception as _exc:
                                pass
                    except Exception:
                        continue
        except Exception:
            continue

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    API Fuzzing 2026-Grade — REST Discovery, GraphQL Introspection, gRPC Enum, Auth Bypass.

    Técnicas: REST endpoint discovery (40+ paths), GraphQL introspection e query testing,
    gRPC reflection/health check, authentication bypass (null token, none-alg JWT,
    IP spoof, URL override), rate limiting testing, mass assignment detection.
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "rest_endpoints": [],
        "graphql": [],
        "grpc": [],
        "auth_bypass": [],
        "rate_limiting": [],
        "mass_assignment": [],
    }

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    resultado["rest_endpoints"] = _discover_rest_endpoints(clean_target)
    resultado["graphql"] = _test_graphql_introspection(clean_target)
    resultado["grpc"] = _test_grpc_enumeration(clean_target)
    resultado["auth_bypass"] = _test_auth_bypass(clean_target)
    resultado["rate_limiting"] = _test_rate_limiting(clean_target)
    resultado["mass_assignment"] = _test_mass_assignment(clean_target)

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total > 0 else "LIMPO"),
    }

    return {
        "plugin": "api_fuzzing",
        "versao": "2026.1",
        "tecnicas": [
            "rest_discovery",
            "graphql_introspection",
            "grpc_enumeration",
            "auth_bypass",
            "rate_limiting",
            "mass_assignment",
        ],
        "resultados": resultado,
    }
