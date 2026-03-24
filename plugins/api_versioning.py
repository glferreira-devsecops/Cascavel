# plugins/api_versioning.py — Cascavel 2026 Intelligence

import requests

API_PREFIXES = [
    "/api",
    "/v1",
    "/v2",
    "/v3",
    "/v4",
    "/v0",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/api/v0",
    "/api/beta",
    "/api/alpha",
    "/api/internal",
    "/api/legacy",
    "/api/dev",
    "/api/staging",
    "/api/test",
    "/api/private",
    "/api/admin",
    "/api/debug",
]

DEPRECATED_INDICATORS = ["deprecated", "sunset", "end-of-life", "legacy", "x-api-warn", "x-api-deprecated", "obsolete"]

HEADER_VERSION_HEADERS = [
    "X-API-Version",
    "API-Version",
    "X-Version",
    "Accept-Version",
    "X-Api-Revision",
]


def _enumerate_versions(target):
    """Enumera versões de API ativas no alvo."""
    vulns = []
    active_versions = []
    for prefix in API_PREFIXES:
        try:
            resp = requests.get(f"http://{target}{prefix}/", timeout=5)
            if resp.status_code in (200, 301, 302, 401, 403):
                active_versions.append({"prefix": prefix, "status": resp.status_code})
                headers_lower = str(resp.headers).lower()
                body_lower = resp.text.lower()

                for indicator in DEPRECATED_INDICATORS:
                    if indicator in headers_lower or indicator in body_lower:
                        vulns.append(
                            {
                                "tipo": "API_DEPRECATED_ACTIVE",
                                "endpoint": prefix,
                                "severidade": "ALTO",
                                "indicador": indicator,
                                "descricao": f"API {prefix} marcada como deprecated mas ainda ativa!",
                            }
                        )
                        break

                # Check Sunset header (RFC 8594)
                sunset = resp.headers.get("Sunset", "")
                if sunset:
                    vulns.append(
                        {
                            "tipo": "API_SUNSET_HEADER",
                            "endpoint": prefix,
                            "sunset": sunset,
                            "severidade": "MEDIO",
                            "descricao": f"API tem Sunset header: {sunset}",
                        }
                    )

                # Check for different auth requirements
                if resp.status_code == 200 and (
                    "internal" in prefix or "admin" in prefix or "debug" in prefix or "private" in prefix
                ):
                    vulns.append(
                        {
                            "tipo": "SHADOW_API_EXPOSED",
                            "endpoint": prefix,
                            "severidade": "CRITICO",
                            "descricao": f"API interna/admin/debug acessível sem auth: {prefix}!",
                        }
                    )

        except Exception:
            continue

    if len(active_versions) > 3:
        vulns.append(
            {
                "tipo": "API_MULTIPLE_VERSIONS",
                "versoes": len(active_versions),
                "severidade": "MEDIO",
                "descricao": f"{len(active_versions)} versões de API ativas — attack surface ampliada!",
                "versoes_encontradas": active_versions[:15],
            }
        )

    return vulns, active_versions


def _check_header_versioning(target):
    """Testa se API aceita versionamento por header."""
    vulns = []
    for header in HEADER_VERSION_HEADERS:
        try:
            resp = requests.get(
                f"http://{target}/api/",
                headers={header: "99"},
                timeout=5,
            )
            api_version = resp.headers.get(header, "")
            if "99" in api_version or resp.status_code == 200:
                vulns.append(
                    {
                        "tipo": "HEADER_VERSION_ACCEPTED",
                        "header": header,
                        "severidade": "BAIXO",
                        "descricao": f"API aceita versionamento via header {header}",
                    }
                )
        except Exception:
            continue
    return vulns


def _check_old_version_vulns(target, active_versions):
    """Verifica se versões antigas expõem mais dados."""
    vulns = []
    if len(active_versions) < 2:
        return vulns

    # Compare response sizes between versions
    responses = {}
    for ver in active_versions[:5]:
        try:
            resp = requests.get(f"http://{target}{ver['prefix']}/users", timeout=5)
            if resp.status_code == 200:
                responses[ver["prefix"]] = len(resp.text)
        except Exception:
            continue

    if responses:
        sizes = list(responses.values())
        if max(sizes) > min(sizes) * 2:
            vulns.append(
                {
                    "tipo": "VERSION_DATA_LEAK",
                    "severidade": "ALTO",
                    "descricao": "Versões antigas da API retornam mais dados que versões novas!",
                    "tamanhos": responses,
                }
            )

    return vulns


def run(target, ip, open_ports, banners):
    """
    API Versioning Scanner 2026-Grade — Shadow APIs, Deprecation, Data Leak.

    Técnicas: 21 API prefixes (internal/admin/debug/staging/private),
    deprecated endpoint detection, Sunset header (RFC 8594),
    shadow API exposure (internal/admin without auth), header versioning
    (X-API-Version/Accept-Version), version data leak comparison,
    multiple version attack surface analysis.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    ver_vulns, active_versions = _enumerate_versions(target)
    vulns.extend(ver_vulns)
    vulns.extend(_check_header_versioning(target))
    vulns.extend(_check_old_version_vulns(target, active_versions))

    return {
        "plugin": "api_versioning",
        "versao": "2026.1",
        "tecnicas": [
            "version_enum",
            "deprecated_detection",
            "sunset_header",
            "shadow_api",
            "header_versioning",
            "version_data_leak",
        ],
        "resultados": vulns if vulns else "Nenhum problema de versionamento detectado",
    }
