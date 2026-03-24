# plugins/api_enum.py — Cascavel 2026 Intelligence

import requests

DOC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/redoc",
    "/docs",
    "/api/docs",
    "/api/swagger",
    "/graphql/schema",
    "/.well-known/openapi.json",
    "/api/v1/docs",
    "/api/v2/docs",
    "/api/v3/docs",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/env",
    "/health",
    "/info",
    "/metrics",
    "/prometheus",
    "/_cat/indices",
    "/_cluster/health",
]

API_ENDPOINTS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/api/v4/",
    "/api/v0/",
    "/api/beta/",
    "/api/alpha/",
    "/api/internal/",
    "/api/legacy/",
    "/api/dev/",
    "/api/staging/",
    "/api/test/",
    "/api/admin/",
    "/api/private/",
    "/api/protected/",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def _classify_doc(path, resp):
    """Classifica o tipo de documentação encontrada."""
    entry = {"path": path, "status": 200, "tamanho": len(resp.text)}
    text_lower = resp.text.lower()

    if any(kw in text_lower for kw in ["swagger", "openapi", "paths"]):
        entry["tipo"] = "SWAGGER/OPENAPI"
        entry["severidade"] = "ALTO"
        try:
            spec = resp.json()
            paths = list(spec.get("paths", {}).keys())
            entry["endpoints_expostos"] = len(paths)
            entry["amostra"] = paths[:15]
            # Extract security schemes
            sec = spec.get("securityDefinitions", spec.get("components", {}).get("securitySchemes", {}))
            if sec:
                entry["auth_schemes"] = list(sec.keys())
        except Exception:
            pass
    elif "actuator" in path:
        entry["tipo"] = "SPRING_ACTUATOR"
        if "env" in path or "configprops" in path:
            entry["severidade"] = "CRITICO"
        elif "heapdump" in path or "threaddump" in path:
            entry["severidade"] = "CRITICO"
        else:
            entry["severidade"] = "ALTO"
    elif "_cat" in path or "_cluster" in path:
        entry["tipo"] = "ELASTICSEARCH"
        entry["severidade"] = "CRITICO"
    elif "prometheus" in path or "metrics" in path:
        entry["tipo"] = "METRICS/PROMETHEUS"
        entry["severidade"] = "MEDIO"
    elif any(kw in text_lower for kw in ["health", "status", "uptime"]):
        entry["tipo"] = "HEALTH_CHECK"
        entry["severidade"] = "BAIXO"
    else:
        entry["tipo"] = "INFO_DISCLOSURE"
        entry["severidade"] = "MEDIO"

    return entry


def _enumerate_methods(target, prefix):
    """Enumera métodos HTTP aceitos em cada endpoint."""
    methods_accepted = []
    try:
        resp = requests.options(f"http://{target}{prefix}", timeout=5)
        allow = resp.headers.get("Allow", "")
        if allow:
            methods_accepted = [m.strip() for m in allow.split(",")]
    except Exception:
        pass
    return methods_accepted


def _test_method_override(target, prefix):
    """Testa HTTP method override."""
    vulns = []
    override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]
    for header in override_headers:
        try:
            resp = requests.post(
                f"http://{target}{prefix}",
                headers={header: "DELETE"},
                timeout=5,
            )
            if resp.status_code in [200, 204]:
                vulns.append(
                    {
                        "tipo": "METHOD_OVERRIDE_ACCEPTED",
                        "endpoint": prefix,
                        "header": header,
                        "severidade": "ALTO",
                        "descricao": f"HTTP method override via {header} — DELETE simulado!",
                    }
                )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    API Enumerator 2026-Grade — Docs, Actuators, Methods, Override.

    Técnicas: 33 doc/actuator/metrics paths, 16 API version prefixes,
    Swagger/OpenAPI spec parsing (paths + auth schemes),
    Spring Actuator (env/heapdump/configprops/beans/mappings),
    Elasticsearch/_cat, Prometheus/metrics, method enumeration (OPTIONS),
    HTTP method override (X-HTTP-Method-Override/X-Method-Override/_method).
    """
    _ = (ip, open_ports, banners)
    resultado = {"docs_expostas": [], "endpoints_ativos": [], "vulns": []}

    # Docs scanning
    for path in DOC_PATHS:
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                entry = _classify_doc(path, resp)
                resultado["docs_expostas"].append(entry)
        except Exception:
            continue

    # API endpoint enumeration
    for prefix in API_ENDPOINTS:
        try:
            resp = requests.get(f"http://{target}{prefix}", timeout=3)
            if resp.status_code in [200, 301, 302, 401, 403]:
                ep_info = {"prefix": prefix, "status": resp.status_code}
                methods = _enumerate_methods(target, prefix)
                if methods:
                    ep_info["methods_allowed"] = methods
                resultado["endpoints_ativos"].append(ep_info)

                # Method override
                resultado["vulns"].extend(_test_method_override(target, prefix))
        except Exception:
            continue

    return {
        "plugin": "api_enum",
        "versao": "2026.1",
        "tecnicas": [
            "doc_scanning",
            "actuator_probe",
            "elasticsearch_probe",
            "prometheus_probe",
            "method_enumeration",
            "method_override",
        ],
        "resultados": resultado,
    }
