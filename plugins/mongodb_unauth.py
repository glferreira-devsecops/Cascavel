# plugins/mongodb_unauth.py — Cascavel 2026 Intelligence
import socket

import requests

MONGO_PORTS = [27017, 27018, 27019, 27020]

ISMASTER_QUERY = (
    b"\x3f\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\xd4\x07\x00\x00"
    b"\x00\x00\x00\x00"
    b"admin.$cmd\x00"
    b"\x00\x00\x00\x00"
    b"\x01\x00\x00\x00"
    b"\x13\x00\x00\x00"
    b"\x01ismaster\x00\x00\x00\xf0?\x00"
)


def _probe_mongodb(target, port):
    """Envia ismaster query e verifica resposta."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(ISMASTER_QUERY)
        response = sock.recv(4096)
        sock.close()
        if len(response) > 4:
            return response.decode(errors="ignore")
    except Exception:
        pass
    return ""


def _check_mongo_http(target, port):
    """Verifica interfaces HTTP do MongoDB."""
    vulns = []
    http_ports = [port + 1000, 28017]
    for hp in http_ports:
        try:
            resp = requests.get(f"http://{target}:{hp}/", timeout=5)
            if resp.status_code == 200 and "mongodb" in resp.text.lower():
                vulns.append(
                    {
                        "tipo": "MONGODB_HTTP_INTERFACE",
                        "porta": hp,
                        "severidade": "CRITICO",
                        "descricao": f"MongoDB HTTP interface exposta em :{hp}!",
                    }
                )
        except Exception:
            pass
    return vulns


def _check_mongo_express(target):
    """Verifica Mongo Express (admin web UI) sem auth."""
    vulns = []
    for port in [8081, 8082, 8888]:
        try:
            resp = requests.get(f"http://{target}:{port}/", timeout=5)
            if resp.status_code == 200 and any(
                k in resp.text.lower() for k in ["mongo express", "mongo-express", "databases"]
            ):
                vulns.append(
                    {
                        "tipo": "MONGO_EXPRESS_UNAUTH",
                        "porta": port,
                        "severidade": "CRITICO",
                        "descricao": f"Mongo Express (web admin) sem auth em :{port}!",
                    }
                )
        except Exception:
            continue
    return vulns


def _analyze_mongo_response(response, port):
    """Analisa resposta MongoDB para info disclosure e vulns."""
    vulns = []
    if not response:
        return vulns

    indicators = ["ismaster", "maxBsonObjectSize", "maxMessageSizeBytes", "ok"]
    if any(ind in response for ind in indicators):
        vuln = {
            "tipo": "MONGODB_UNAUTH",
            "porta": port,
            "severidade": "CRITICO",
            "descricao": f"MongoDB sem auth em :{port} — dump de dados possível!",
        }
        if "version" in response:
            start = response.find("version")
            vuln["version_leak"] = response[start : start + 30]
        if "setName" in response:
            start = response.find("setName")
            vuln["replica_set"] = response[start : start + 40]
            vuln["descricao"] += " (Replica Set detectado)"
        vulns.append(vuln)

    return vulns


def _check_mongos(target):
    """Verifica mongos (router) exposto — indica sharded cluster."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, 27017))
        sock.send(ISMASTER_QUERY)
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        if "mongos" in response.lower() or "isdbgrid" in response.lower():
            return {
                "tipo": "MONGOS_EXPOSED",
                "porta": 27017,
                "severidade": "CRITICO",
                "descricao": "Mongos router exposto — acesso a sharded cluster inteiro!",
            }
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner MongoDB 2026-Grade — Unauth, HTTP, Mongo Express, Mongos.

    Técnicas: ismaster query (4 ports), HTTP interface, Mongo Express
    web admin (3 ports), replica set detection, version disclosure,
    mongos/sharded cluster detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for port in MONGO_PORTS:
        response = _probe_mongodb(target, port)
        vulns.extend(_analyze_mongo_response(response, port))
        vulns.extend(_check_mongo_http(target, port))

    vulns.extend(_check_mongo_express(target))
    mongos = _check_mongos(target)
    if mongos:
        vulns.append(mongos)

    return {
        "plugin": "mongodb_unauth",
        "versao": "2026.1",
        "tecnicas": [
            "ismaster_probe",
            "http_interface",
            "mongo_express",
            "version_disclosure",
            "replica_set",
            "mongos_detection",
        ],
        "resultados": vulns if vulns else "Nenhum MongoDB exposto",
    }
