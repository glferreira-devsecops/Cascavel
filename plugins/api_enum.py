# plugins/api_enum.py
def run(target, ip, open_ports, banners):
    """
    Enumeração de APIs REST: endpoints, versões, documentação exposta.
    Descobre Swagger/OpenAPI, versões de API, e endpoints não documentados.
    """
    import requests
    import json

    resultado = {"docs_expostas": [], "endpoints_ativos": [], "vulns": []}

    # 1. Documentação de API exposta
    doc_paths = [
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
        "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui.html", "/swagger-ui/", "/redoc", "/docs",
        "/api/docs", "/api/swagger", "/graphql/schema",
        "/.well-known/openapi.json", "/api/v1/docs", "/api/v2/docs",
        "/actuator", "/actuator/env", "/actuator/health",
        "/env", "/health", "/info", "/metrics",
    ]

    for path in doc_paths:
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                entry = {"path": path, "status": 200, "tamanho": len(resp.text)}

                # Detectar tipo de doc
                if any(kw in resp.text.lower() for kw in ["swagger", "openapi", "paths"]):
                    entry["tipo"] = "SWAGGER/OPENAPI"
                    entry["severidade"] = "ALTO"
                    # Extrair endpoints do spec
                    try:
                        spec = resp.json()
                        paths = list(spec.get("paths", {}).keys())
                        entry["endpoints_expostos"] = len(paths)
                        entry["amostra"] = paths[:10]
                    except Exception:
                        pass
                elif "actuator" in path:
                    entry["tipo"] = "SPRING_ACTUATOR"
                    entry["severidade"] = "CRITICO" if "env" in path else "ALTO"
                elif any(kw in resp.text.lower() for kw in ["health", "status", "uptime"]):
                    entry["tipo"] = "HEALTH_CHECK"
                    entry["severidade"] = "BAIXO"
                else:
                    entry["tipo"] = "INFO_DISCLOSURE"
                    entry["severidade"] = "MEDIO"

                resultado["docs_expostas"].append(entry)
        except Exception:
            continue

    # 2. Enumeração de versões de API
    for version in ["v1", "v2", "v3", "v4"]:
        url = f"http://{target}/api/{version}/"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code in [200, 301, 302, 401, 403]:
                resultado["endpoints_ativos"].append({
                    "versao": version,
                    "status": resp.status_code,
                })
        except Exception:
            continue

    return {"plugin": "api_enum", "resultados": resultado}
