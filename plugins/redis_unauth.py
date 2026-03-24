# plugins/redis_unauth.py — Cascavel 2026 Intelligence
import socket


REDIS_PORTS = [6379, 6380, 6381, 6382, 26379]

REDIS_COMMANDS = [
    ("INFO\r\n", "redis_version", "REDIS_INFO_EXPOSED", "CRITICO"),
    ("CONFIG GET *\r\n", "dir", "REDIS_CONFIG_EXPOSED", "CRITICO"),
    ("DBSIZE\r\n", "keys=", "REDIS_DBSIZE", "ALTO"),
    ("CLIENT LIST\r\n", "addr=", "REDIS_CLIENT_LIST", "ALTO"),
    ("KEYS *\r\n", "$", "REDIS_KEYS_ENUM", "CRITICO"),
    ("CLUSTER INFO\r\n", "cluster_", "REDIS_CLUSTER_INFO", "ALTO"),
    ("ACL LIST\r\n", "user", "REDIS_ACL_LIST", "CRITICO"),
    ("MODULE LIST\r\n", "", "REDIS_MODULES", "MEDIO"),
    ("SLOWLOG GET 10\r\n", "", "REDIS_SLOWLOG", "MEDIO"),
    ("DEBUG OBJECT\r\n", "", "REDIS_DEBUG", "ALTO"),
]


def _send_redis_cmd(target, port, command):
    """Envia comando Redis via socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(command.encode())
        response = sock.recv(8192).decode(errors="ignore")
        sock.close()
        return response
    except Exception:
        return ""


def _check_redis_auth(target, port):
    """Verifica comandos Redis aceitos sem autenticação."""
    vulns = []
    for cmd, indicator, tipo, sev in REDIS_COMMANDS:
        response = _send_redis_cmd(target, port, cmd)
        if response and "-NOAUTH" not in response and "-ERR" not in response:
            if indicator and indicator in response.lower():
                vuln = {
                    "tipo": tipo, "porta": port, "severidade": sev,
                    "amostra": response[:200],
                    "descricao": f"Redis sem auth em :{port} — '{cmd.strip()}' executado!",
                }
                # Extract version
                if "redis_version" in response:
                    for line in response.split("\r\n"):
                        if line.startswith("redis_version:"):
                            vuln["redis_version"] = line.split(":")[1]
                        if line.startswith("os:"):
                            vuln["os"] = line.split(":")[1]
                vulns.append(vuln)
            elif not indicator and response.startswith("*") or response.startswith("+"):
                vulns.append({
                    "tipo": tipo, "porta": port, "severidade": sev,
                    "descricao": f"Redis '{cmd.strip()}' aceito sem auth!",
                })
    return vulns


def _check_redis_rce(target, port):
    """Verifica possibilidade de RCE via Redis."""
    vulns = []
    # CONFIG GET dir
    response = _send_redis_cmd(target, port, "CONFIG GET dir\r\n")
    if "dir" in response.lower() and "-ERR" not in response and "-NOAUTH" not in response:
        vulns.append({
            "tipo": "REDIS_RCE_VIA_CONFIG", "porta": port,
            "severidade": "CRITICO",
            "descricao": "CONFIG GET dir — RCE via crontab/webshell/SSH key injection!",
        })

    # SCRIPT EXISTS (Lua)
    response = _send_redis_cmd(target, port, "EVAL 'return 1' 0\r\n")
    if ":1" in response and "-ERR" not in response:
        vulns.append({
            "tipo": "REDIS_LUA_ENABLED", "porta": port,
            "severidade": "ALTO",
            "descricao": "Lua scripting habilitado — SSRF/data exfil via EVAL!",
        })

    # SLAVEOF probe (replication attack)
    response = _send_redis_cmd(target, port, "INFO replication\r\n")
    if "connected_slaves" in response:
        vulns.append({
            "tipo": "REDIS_REPLICATION_INFO", "porta": port,
            "severidade": "ALTO",
            "descricao": "Replication info exposta — SLAVEOF attack possível!",
        })

    return vulns


def _check_sentinel(target):
    """Verifica Redis Sentinel exposto."""
    vulns = []
    response = _send_redis_cmd(target, 26379, "SENTINEL masters\r\n")
    if response and "-ERR" not in response and len(response) > 10:
        vulns.append({
            "tipo": "REDIS_SENTINEL_EXPOSED", "porta": 26379,
            "severidade": "CRITICO",
            "descricao": "Redis Sentinel exposto — cluster takeover possível!",
        })
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Redis 2026-Grade — Unauth, RCE, Lua, Sentinel, SLAVEOF.

    Técnicas: 10 Redis commands (INFO/CONFIG/KEYS/ACL/CLUSTER/SLOWLOG),
    5 ports (6379-6382 + 26379 Sentinel), RCE probes (CONFIG dir/Lua EVAL),
    replication/SLAVEOF attack detection, Sentinel exposure,
    version/OS extraction.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for port in REDIS_PORTS:
        auth_vulns = _check_redis_auth(target, port)
        if auth_vulns:
            vulns.extend(auth_vulns)
            vulns.extend(_check_redis_rce(target, port))

    vulns.extend(_check_sentinel(target))

    return {
        "plugin": "redis_unauth", "versao": "2026.1",
        "tecnicas": ["command_probe", "rce_config", "lua_eval",
                      "slaveof_attack", "sentinel", "acl_enum"],
        "resultados": vulns if vulns else "Nenhum Redis exposto",
    }
