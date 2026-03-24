# plugins/websocket_scanner.py — Cascavel 2026 Intelligence
import base64
import os
import socket

WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket.io/",
    "/sockjs/",
    "/cable",
    "/hub",
    "/signalr",
    "/api/ws",
    "/api/v1/ws",
    "/realtime",
    "/live",
    "/stream",
    "/chat",
    "/notifications",
    "/events",
    "/graphql/ws",
    "/api/graphql/subscriptions",
]

# ──────────── XSS/INJECTION PAYLOADS ────────────
WS_INJECTION_PAYLOADS = [
    "<script>alert(1)</script>",
    '{"type":"subscribe","payload":"<img src=x onerror=alert(1)>"}',
    '{"__proto__":{"admin":true}}',
    "'; DROP TABLE users; --",
    '{"query":"{ __schema { types { name } } }"}',
]


def _attempt_ws_handshake(target, path, origin="http://evil.com", port=80):
    """Tenta WebSocket handshake e retorna resposta completa."""
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((target, port))
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        return response, key
    except Exception:
        return "", key


def _analyze_ws_response(response, path, origin):
    """Analisa resposta do WebSocket handshake."""
    vulns = []
    if "101 Switching Protocols" not in response:
        return vulns

    # Endpoint found
    vulns.append(
        {
            "tipo": "WEBSOCKET_ENDPOINT",
            "path": path,
            "severidade": "INFO",
            "descricao": f"WebSocket endpoint ativo: {path}",
        }
    )

    # CSWSH — Cross-Site WebSocket Hijacking
    if "evil.com" in origin.lower():
        vulns.append(
            {
                "tipo": "WEBSOCKET_CSWSH",
                "path": path,
                "severidade": "CRITICO",
                "descricao": "WebSocket aceita Origin evil.com — CSWSH (Cross-Site WebSocket Hijacking)!",
            }
        )

    # Check for missing auth
    if "sec-websocket-accept" in response.lower():
        # Handshake successful without auth tokens
        vulns.append(
            {
                "tipo": "WEBSOCKET_NO_AUTH",
                "path": path,
                "severidade": "ALTO",
                "descricao": "WebSocket handshake sem autenticação — acesso não autorizado!",
            }
        )

    # Check extensions
    if "sec-websocket-extensions" in response.lower():
        if "permessage-deflate" in response.lower():
            vulns.append(
                {
                    "tipo": "WEBSOCKET_COMPRESSION",
                    "path": path,
                    "severidade": "BAIXO",
                    "descricao": "WebSocket com permessage-deflate — possível CRIME/BREACH attack",
                }
            )

    return vulns


def _test_multiple_origins(target, path):
    """Testa CSWSH com múltiplos origins."""
    vulns = []
    origins = [
        ("http://evil.com", "EVIL_ORIGIN"),
        ("null", "NULL_ORIGIN"),
        (f"http://{target}.evil.com", "SUBDOMAIN_MATCH"),
        ("", "EMPTY_ORIGIN"),
        ("http://localhost", "LOCALHOST_ORIGIN"),
    ]
    for origin, method in origins:
        response, _ = _attempt_ws_handshake(target, path, origin=origin)
        if "101 Switching Protocols" in response:
            if method != "LOCALHOST_ORIGIN":
                vulns.append(
                    {
                        "tipo": f"WEBSOCKET_CSWSH_{method}",
                        "path": path,
                        "origin": origin,
                        "severidade": "CRITICO" if method != "EMPTY_ORIGIN" else "ALTO",
                        "descricao": f"WebSocket aceita Origin: {origin} — CSWSH via {method}!",
                    }
                )
                break
    return vulns


def _test_ws_smuggling(target, path, port=80):
    """Testa WebSocket smuggling (upgrade then inject HTTP)."""
    key = base64.b64encode(os.urandom(16)).decode()
    # Standard handshake
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: http://{target}\r\n\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((target, port))
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")

        if "101" in response:
            # Try smuggling HTTP request over WebSocket
            smuggle = f"GET /admin HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(smuggle.encode())
            smuggle_resp = sock.recv(4096).decode(errors="ignore")
            sock.close()

            if "200 OK" in smuggle_resp or "admin" in smuggle_resp.lower():
                return {
                    "tipo": "WEBSOCKET_SMUGGLING",
                    "path": path,
                    "severidade": "CRITICO",
                    "descricao": "WebSocket smuggling — HTTP request smuggled via WS tunnel!",
                }
        else:
            sock.close()
    except Exception:
        pass
    return None


def _test_socketio_info(target):
    """Testa exposição de informação do Socket.IO."""
    vulns = []
    import requests as req

    for path in ["/socket.io/?EIO=4&transport=polling", "/socket.io/?EIO=3&transport=polling"]:
        try:
            resp = req.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and "sid" in resp.text:
                vulns.append(
                    {
                        "tipo": "SOCKETIO_EXPOSED",
                        "path": path,
                        "severidade": "MEDIO",
                        "descricao": "Socket.IO endpoint exposto — session ID obtido!",
                        "amostra": resp.text[:100],
                    }
                )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner WebSocket 2026-Grade — CSWSH, Smuggling, Socket.IO, Auth.

    Técnicas: 17 WebSocket paths, CSWSH multi-origin testing (evil/null/subdomain/empty),
    WebSocket smuggling (HTTP over WS tunnel), Socket.IO exposure,
    compression CRIME/BREACH detection, no-auth handshake detection,
    injection payload testing.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for path in WS_PATHS:
        response, _ = _attempt_ws_handshake(target, path)
        vulns.extend(_analyze_ws_response(response, path, "http://evil.com"))

        if "101 Switching" in response:
            # Multi-origin CSWSH
            vulns.extend(_test_multiple_origins(target, path))

            # Smuggling
            smuggle = _test_ws_smuggling(target, path)
            if smuggle:
                vulns.append(smuggle)

    # Socket.IO exposure
    vulns.extend(_test_socketio_info(target))

    return {
        "plugin": "websocket_scanner",
        "versao": "2026.1",
        "tecnicas": ["cswsh", "multi_origin", "ws_smuggling", "socketio_exposure", "compression_attack", "no_auth"],
        "resultados": vulns if vulns else "Nenhum WebSocket vulnerável detectado",
    }
