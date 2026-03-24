# plugins/oauth_scanner.py — Cascavel 2026 Intelligence
import requests
import urllib.parse
import re


OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/.well-known/openid-configuration",
    "/oauth/token", "/api/oauth/callback", "/auth/callback",
    "/login/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
    "/oauth2/token", "/api/v1/oauth/authorize", "/api/v1/oauth/token",
    "/.well-known/oauth-authorization-server",
]

# ──────────── REDIRECT URI BYPASS ────────────
REDIRECT_BYPASSES = [
    ("https://evil.com", "DIRECT_EVIL"),
    ("https://evil.com@legitimate.com", "AT_SIGN"),
    ("https://legitimate.com.evil.com", "SUBDOMAIN_MATCH"),
    ("//evil.com", "PROTOCOL_RELATIVE"),
    ("https://legitimate.com%40evil.com", "ENCODED_AT"),
    ("https://legitimate.com/..;/evil", "PATH_TRAVERSAL"),
    ("https://evil.com#@legitimate.com", "FRAGMENT_BYPASS"),
    ("https://legitimate.com%2F%2Fevil.com", "DOUBLE_SLASH"),
    ("https://legitimate.com\\@evil.com", "BACKSLASH_BYPASS"),
    ("http://legitimate.com", "HTTP_DOWNGRADE"),
    ("https://legitimate.com/callback?next=https://evil.com", "OPEN_REDIRECT_CHAIN"),
    ("https://legitimate.com/callback/../evil", "DOT_DOT_SLASH"),
    ("https://legitimate.com%00.evil.com", "NULL_BYTE"),
    ("javascript:alert(1)", "JAVASCRIPT_URI"),
    ("data:text/html,<script>alert(1)</script>", "DATA_URI"),
]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("client", "client"),
    ("test", "test"),
    ("app", "secret"),
    ("default", "default"),
    ("", ""),
]


def _check_openid_config(target):
    """Verifica exposição do OpenID Configuration e analisa endpoints."""
    vulns = []
    for path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200 and "issuer" in resp.text:
                vulns.append({
                    "tipo": "OPENID_CONFIG_EXPOSED", "url": url,
                    "severidade": "MEDIO",
                    "descricao": "OpenID Configuration exposta — enumeration de endpoints",
                })
                # Check for dangerous scopes
                if "scopes_supported" in resp.text:
                    try:
                        config = resp.json()
                        scopes = config.get("scopes_supported", [])
                        dangerous_scopes = [s for s in scopes if s in ["admin", "write", "delete", "all"]]
                        if dangerous_scopes:
                            vulns.append({
                                "tipo": "OAUTH_DANGEROUS_SCOPES", "severidade": "ALTO",
                                "scopes": dangerous_scopes,
                                "descricao": "Scopes perigosos disponíveis!",
                            })
                    except Exception:
                        pass
                # Check for PKCE support
                if "code_challenge_methods_supported" not in resp.text:
                    vulns.append({
                        "tipo": "OAUTH_NO_PKCE", "severidade": "ALTO",
                        "descricao": "PKCE não suportado — vulnerável a authorization code interception!",
                    })
        except Exception:
            pass
    return vulns


def _check_redirect_bypass(target):
    """Testa bypass de redirect_uri no fluxo OAuth."""
    vulns = []
    for ep in ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize"]:
        for bypass, method in REDIRECT_BYPASSES:
            url = f"http://{target}{ep}?response_type=code&redirect_uri={urllib.parse.quote(bypass, safe='')}&client_id=test"
            try:
                resp = requests.get(url, timeout=8, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if "evil.com" in location or bypass in location:
                    vulns.append({
                        "tipo": "OAUTH_REDIRECT_BYPASS", "metodo": method,
                        "bypass": bypass, "location": location[:200],
                        "severidade": "CRITICO",
                        "descricao": f"redirect_uri bypass via {method} — token theft!",
                    })
                    return vulns  # One is enough
                # Check for token in fragment
                if "#access_token=" in location:
                    vulns.append({
                        "tipo": "OAUTH_IMPLICIT_FLOW", "severidade": "ALTO",
                        "descricao": "Implicit flow detectado — token no fragment URL!",
                    })
            except Exception:
                continue
    return vulns


def _check_token_leak(target):
    """Testa token endpoint com credenciais default e grant types inseguros."""
    vulns = []
    token_endpoints = ["/oauth/token", "/oauth2/token", "/api/v1/oauth/token"]

    for ep in token_endpoints:
        url = f"http://{target}{ep}"

        # Default credentials
        for client_id, client_secret in DEFAULT_CREDS:
            try:
                resp = requests.post(url, data={
                    "grant_type": "client_credentials",
                    "client_id": client_id, "client_secret": client_secret,
                }, timeout=8)
                if resp.status_code == 200 and "access_token" in resp.text:
                    vulns.append({
                        "tipo": "OAUTH_DEFAULT_CREDS", "severidade": "CRITICO",
                        "client_id": client_id,
                        "descricao": f"Token obtido com credenciais default ({client_id}:{client_secret})!",
                    })
                    break
            except Exception:
                continue

        # Password grant type (insecure)
        try:
            resp = requests.post(url, data={
                "grant_type": "password",
                "username": "admin", "password": "admin",
                "client_id": "test",
            }, timeout=5)
            if resp.status_code == 200 and "access_token" in resp.text:
                vulns.append({
                    "tipo": "OAUTH_PASSWORD_GRANT", "severidade": "ALTO",
                    "descricao": "Password grant type aceito — credenciais expostas ao client!",
                })
        except Exception:
            pass

    return vulns


def _check_pkce_downgrade(target):
    """Testa se PKCE pode ser removido do fluxo (downgrade attack)."""
    vulns = []
    for ep in ["/oauth/authorize", "/oauth2/authorize"]:
        # Request com PKCE
        url_pkce = f"http://{target}{ep}?response_type=code&client_id=test&code_challenge=test&code_challenge_method=S256&redirect_uri=http://localhost"
        # Request sem PKCE
        url_no_pkce = f"http://{target}{ep}?response_type=code&client_id=test&redirect_uri=http://localhost"
        try:
            r_pkce = requests.get(url_pkce, timeout=5, allow_redirects=False)
            r_no = requests.get(url_no_pkce, timeout=5, allow_redirects=False)
            # Se ambos retornam redirect, PKCE pode ser ignorado
            if r_pkce.status_code in (302, 303) and r_no.status_code in (302, 303):
                vulns.append({
                    "tipo": "OAUTH_PKCE_DOWNGRADE", "severidade": "ALTO",
                    "descricao": "PKCE pode ser removido do fluxo — downgrade attack possível!",
                })
                break
        except Exception:
            continue
    return vulns


def _check_device_flow(target):
    """Testa se device code flow está habilitado e exposto."""
    vulns = []
    for ep in ["/oauth/device/code", "/oauth2/device/code"]:
        try:
            resp = requests.post(f"http://{target}{ep}",
                                  data={"client_id": "test"}, timeout=5)
            if resp.status_code == 200 and "device_code" in resp.text:
                vulns.append({
                    "tipo": "OAUTH_DEVICE_FLOW_EXPOSED", "severidade": "MEDIO",
                    "descricao": "Device code flow habilitado — phishing social engineering vector!",
                })
        except Exception:
            continue
    return vulns


def _check_state_parameter(target):
    """Verifica se state parameter é requerido no fluxo OAuth."""
    for ep in ["/oauth/authorize", "/oauth2/authorize"]:
        url = f"http://{target}{ep}?response_type=code&client_id=test&redirect_uri=http://localhost"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in (302, 303) and "state=" not in resp.headers.get("Location", ""):
                return {
                    "tipo": "OAUTH_NO_STATE", "severidade": "ALTO",
                    "descricao": "State parameter não requerido — CSRF no fluxo OAuth!",
                }
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner OAuth/OIDC 2026-Grade — Misconfig, Redirect Bypass, PKCE, Device Flow.

    Técnicas: 15 redirect_uri bypass variants, OpenID config exposure + scope analysis,
    PKCE downgrade attack, device code flow detection, password grant type check,
    default credentials (6 combos), state parameter validation, implicit flow detection,
    dangerous scopes analysis.
    CVEs: CVE-2025-4143, CVE-2025-4144.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    vulns.extend(_check_openid_config(target))
    vulns.extend(_check_redirect_bypass(target))
    vulns.extend(_check_token_leak(target))
    vulns.extend(_check_pkce_downgrade(target))
    vulns.extend(_check_device_flow(target))

    state = _check_state_parameter(target)
    if state:
        vulns.append(state)

    return {
        "plugin": "oauth_scanner",
        "versao": "2026.1",
        "tecnicas": ["redirect_bypass", "pkce_downgrade", "device_flow",
                      "default_creds", "password_grant", "state_csrf",
                      "implicit_flow", "scope_analysis"],
        "resultados": vulns if vulns else "Nenhuma falha OAuth detectada",
    }
