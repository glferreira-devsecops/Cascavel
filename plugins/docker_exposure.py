# plugins/docker_exposure.py — Cascavel 2026 Intelligence
import requests

DOCKER_PATHS = {
    "/v2/": ("REGISTRY_ROOT", "ALTO"),
    "/v2/_catalog": ("REGISTRY_CATALOG", "CRITICO"),
    "/version": ("DOCKER_VERSION", "ALTO"),
    "/info": ("DOCKER_INFO", "CRITICO"),
    "/containers/json": ("CONTAINERS_LIST", "CRITICO"),
    "/containers/json?all=true": ("CONTAINERS_ALL", "CRITICO"),
    "/images/json": ("IMAGES_LIST", "CRITICO"),
    "/volumes": ("VOLUMES_LIST", "ALTO"),
    "/networks": ("NETWORKS_LIST", "ALTO"),
    "/swarm": ("SWARM_INFO", "CRITICO"),
    "/nodes": ("SWARM_NODES", "CRITICO"),
    "/services": ("SWARM_SERVICES", "ALTO"),
    "/secrets": ("DOCKER_SECRETS", "CRITICO"),
    "/configs": ("DOCKER_CONFIGS", "CRITICO"),
    "/tasks": ("SWARM_TASKS", "ALTO"),
    "/plugins": ("DOCKER_PLUGINS", "MEDIO"),
    "/system/df": ("DOCKER_DISK_USAGE", "MEDIO"),
    "/events": ("DOCKER_EVENTS", "ALTO"),
    "/_ping": ("DOCKER_PING", "MEDIO"),
}

DOCKER_PORTS = [2375, 2376, 4243, 2377, 9323]
REGISTRY_PORTS = [5000, 5001, 443, 8443]


def _check_docker_api(target, port):
    """Verifica Docker daemon API e analisa containers."""
    vulns = []
    for path, (tipo, sev) in DOCKER_PATHS.items():
        url = f"http://{target}:{port}{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 2:
                vuln = {
                    "tipo": f"DOCKER_{tipo}",
                    "porta": port,
                    "path": path,
                    "severidade": sev,
                    "amostra": resp.text[:200],
                    "descricao": f"Docker API {path} exposta em :{port}!",
                }

                # Analyze containers for privileged mode
                if "containers" in path:
                    try:
                        containers = resp.json()
                        if isinstance(containers, list):
                            vuln["containers_count"] = len(containers)
                            for c in containers:
                                if c.get("HostConfig", {}).get("Privileged"):
                                    vuln["privileged_container"] = True
                                    vuln["severidade"] = "CRITICO"
                                    vuln["descricao"] += " Container privilegiado detectado!"
                                mounts = c.get("Mounts", [])
                                for m in mounts:
                                    if m.get("Source") in ["/", "/etc", "/var/run/docker.sock"]:
                                        vuln["dangerous_mount"] = m["Source"]
                                        vuln["descricao"] += f" Mount perigoso: {m['Source']}"
                    except Exception:
                        pass

                # Analyze secrets
                if "secrets" in path:
                    try:
                        secrets = resp.json()
                        if isinstance(secrets, list) and len(secrets) > 0:
                            vuln["secrets_count"] = len(secrets)
                            vuln["descricao"] = f"{len(secrets)} Docker secrets expostos!"
                    except Exception:
                        pass

                vulns.append(vuln)
        except Exception:
            continue
    return vulns


def _check_registry(target):
    """Enumera Docker Registry e imagens."""
    vulns = []
    for port in REGISTRY_PORTS:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}:{port}/v2/_catalog"
            try:
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code == 200 and "repositories" in resp.text:
                    vuln = {
                        "tipo": "DOCKER_REGISTRY_OPEN",
                        "porta": port,
                        "severidade": "CRITICO",
                        "descricao": "Docker Registry aberto — imagens acessíveis sem auth!",
                    }
                    try:
                        repos = resp.json().get("repositories", [])
                        vuln["repositorios"] = len(repos)
                        vuln["amostra"] = repos[:20]
                        # Try to get tags for first repo
                        if repos:
                            tags_resp = requests.get(
                                f"{scheme}://{target}:{port}/v2/{repos[0]}/tags/list", timeout=5, verify=False
                            )
                            if tags_resp.status_code == 200:
                                vuln["tags_amostra"] = tags_resp.json().get("tags", [])[:10]
                    except Exception:
                        pass
                    vulns.append(vuln)
            except Exception:
                continue
    return vulns


def _check_compose_files(target):
    """Verifica docker-compose e Dockerfiles expostos."""
    vulns = []
    files = [
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/docker-compose.prod.yml",
        "/docker-compose.dev.yml",
        "/docker-compose.override.yml",
        "/Dockerfile",
        "/Dockerfile.prod",
        "/.dockerignore",
    ]
    for f in files:
        try:
            resp = requests.get(f"http://{target}{f}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 20:
                sev = (
                    "CRITICO" if any(s in resp.text.lower() for s in ["password", "secret", "key", "token"]) else "ALTO"
                )
                vulns.append(
                    {
                        "tipo": "DOCKER_COMPOSE_EXPOSED",
                        "path": f,
                        "severidade": sev,
                        "secrets_in_compose": sev == "CRITICO",
                        "descricao": f"Arquivo {f} exposto — infraestrutura mapeável!",
                    }
                )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Docker Exposure 2026-Grade — API, Registry, Compose.

    Técnicas: 19 Docker API paths (containers/images/volumes/networks/
    swarm/secrets/configs/tasks), 5 daemon ports (2375/2376/4243/2377/9323),
    4 registry ports, privileged container detection, dangerous mount analysis
    (docker.sock/root), secrets enumeration, registry tag listing,
    docker-compose/Dockerfile exposure, secret-in-compose detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for port in DOCKER_PORTS:
        vulns.extend(_check_docker_api(target, port))
    vulns.extend(_check_registry(target))
    vulns.extend(_check_compose_files(target))

    return {
        "plugin": "docker_exposure",
        "versao": "2026.1",
        "tecnicas": [
            "docker_api",
            "registry_enum",
            "privileged_detection",
            "mount_analysis",
            "secrets_enum",
            "compose_exposure",
        ],
        "resultados": vulns if vulns else "Nenhuma exposição Docker detectada",
    }
