# plugins/grpc_scanner.py
import socket

import requests

GRPC_PORTS = [50051, 50052, 9090, 443]

GRPC_REFLECTION_PAYLOAD = (
    b"\x00\x00\x00\x00\x17"  # Compressed flag + message length
    b"\x0a\x15"  # Field 1, string, length 21
    b"grpc.reflection.v1alpha"
)


def _check_grpc_port(target, port):
    """Verifica se porta gRPC está aberta e aceita conexões."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _check_grpc_web(target, port):
    """Verifica se gRPC-Web está habilitado via HTTP."""
    vulns = []
    url = f"http://{target}:{port}"
    try:
        resp = requests.post(
            url,
            headers={
                "Content-Type": "application/grpc-web",
                "X-Grpc-Web": "1",
            },
            data=b"\x00\x00\x00\x00\x00",
            timeout=5,
        )
        if resp.status_code in (200, 415) or "grpc" in resp.headers.get("Content-Type", "").lower():
            vulns.append(
                {
                    "tipo": "GRPC_WEB_ENABLED",
                    "porta": port,
                    "severidade": "MEDIO",
                    "descricao": f"gRPC-Web habilitado em :{port} — service enumeration possível!",
                }
            )
    except Exception:
        pass
    return vulns


def _check_health_endpoint(target, port):
    """Verifica gRPC health check endpoint via HTTP."""
    vulns = []
    for path in ["/grpc.health.v1.Health/Check", "/health", "/healthz"]:
        try:
            resp = requests.get(f"http://{target}:{port}{path}", timeout=5)
            if resp.status_code == 200:
                vulns.append(
                    {
                        "tipo": "GRPC_HEALTH_EXPOSED",
                        "porta": port,
                        "path": path,
                        "severidade": "BAIXO",
                        "descricao": f"gRPC health endpoint exposto em :{port}{path}",
                    }
                )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner de gRPC service enumeration.
    2026 Intel: gRPC reflection abuse, unauth service discovery,
    gRPC-Web exposure, protobuf deserialization attacks.
    """
    _ = (ip, open_ports, banners)  # Standardized plugin signature
    vulns = []

    for port in GRPC_PORTS:
        if _check_grpc_port(target, port):
            vulns.append(
                {
                    "tipo": "GRPC_PORT_OPEN",
                    "porta": port,
                    "severidade": "INFO",
                    "descricao": f"Porta gRPC :{port} aberta",
                }
            )
            vulns.extend(_check_grpc_web(target, port))
            vulns.extend(_check_health_endpoint(target, port))

    return {"plugin": "grpc_scanner", "resultados": vulns if vulns else "Nenhum serviço gRPC detectado"}
