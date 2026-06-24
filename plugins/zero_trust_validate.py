"""
[+] Plugin: Zero Trust Architecture Validation
[+] Description: Valida microssegmentação, identidade-based access, least privilege, movimento lateral e verificação contínua
[+] Category: Architecture / Zero Trust
[+] CVSS: 8.0 (High)
[+] Author: CASCAVEL Framework
"""

import socket
import subprocess
import shutil
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def _check_microsegmentation(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica efetividade da microssegmentação de rede."""
    findings = []

    # Check for services that should be behind segmentation
    critical_ports = {
        22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
        9200: "Elasticsearch", 2379: "etcd", 6443: "K8s API",
        8500: "Consul", 8501: "Consul (alt)", 443: "HTTPS",
    }

    exposed_services = []
    for port, service in critical_ports.items():
        if port in ports:
            exposed_services.append(f"{port}/{service}")

    if len(exposed_services) >= 3:
        findings.append({
            "tipo": "MICROSSEGMENTACAO_FRACA",
            "severidade": "ALTO",
            "descricao": f"Múltiplos serviços críticos expostos ({len(exposed_services)}) — microssegmentação insuficiente",
            "evidencia": f"Serviços: {', '.join(exposed_services[:10])}",
            "correcao": "Implementar microssegmentação com firewall policies por workload. Usar service mesh (Istio/Linkerd).",
        })

    # Check network boundaries via traceroute
    if shutil.which("traceroute"):
        try:
            result = subprocess.run(
                ["traceroute", "-m", "10", "-w", "2", ip],
                capture_output=True, text=True, timeout=30
            )
            hops = len([l for l in result.stdout.splitlines() if l.strip() and not l.startswith("traceroute")])
            if hops <= 1:
                findings.append({
                    "tipo": "SEM_SEGMENTACAO_REDE",
                    "severidade": "MEDIO",
                    "descricao": f"Apenas {hops} hop(s) até o alvo — rede flat sem segmentação",
                    "correcao": "Implementar VLANs, firewalls internos e network policies para segmentação.",
                })
        except Exception:
            pass

    # Check for direct database access (should go through API layer)
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
    exposed_dbs = [f"{p}/{s}" for p, s in db_ports.items() if p in ports]
    if exposed_dbs:
        findings.append({
            "tipo": "DB_DIRETAMENTE_ACESSIVEL",
            "severidade": "CRITICO",
            "descricao": f"Banco de dados acessível diretamente: {', '.join(exposed_dbs)} — violação de Zero Trust",
            "correcao": "Bancos devem ser acessíveis APENAS via API/service layer. Bloquear acesso direto com firewall.",
        })

    return findings


def _check_identity_access(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica controles de acesso baseado em identidade."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    # Check for services without authentication
    unauth_checks = [
        (9200, "Elasticsearch", "/_cluster/health"),
        (6379, "Redis", None),  # TCP check
        (27017, "MongoDB", None),  # TCP check
        (2379, "etcd", "/health"),
        (8500, "Consul", "/v1/agent/self"),
        (6443, "K8s API", "/api/v1/namespaces"),
    ]

    for port, service, path in unauth_checks:
        if port not in ports:
            continue
        try:
            if path:
                scheme = "https" if port in [6443, 443] else "http"
                resp = requests.get(
                    f"{scheme}://{ip}:{port}{path}",
                    timeout=5, verify=False
                )
                if resp.status_code == 200:
                    findings.append({
                        "tipo": "IDENTIDADE_SEM_AUTH",
                        "severidade": "CRITICO",
                        "descricao": f"{service} acessível sem autenticação na porta {port} — Zero Trust violado",
                        "evidencia": f"HTTP {resp.status_code}: {resp.text[:150]}",
                        "correcao": f"Exigir autenticação (mTLS/JWT/OAuth) para {service}. Implementar Identity-Aware Proxy.",
                    })
            else:
                # TCP-level check for Redis/MongoDB
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                if port == 6379:
                    sock.send(b"PING\r\n")
                    resp = sock.recv(64)
                    if b"+PONG" in resp:
                        findings.append({
                            "tipo": "REDIS_SEM_AUTH",
                            "severidade": "CRITICO",
                            "descricao": "Redis acessível sem autenticação — Zero Trust violado",
                            "correcao": "Configurar requirepass no Redis. Bloquear acesso direto.",
                        })
                sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception:
            pass

    return findings


def _check_least_privilege(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica enforcement de least privilege."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    # Check for admin interfaces exposed
    admin_endpoints = [
        (8080, "/admin", "Admin Panel"),
        (8080, "/manage", "Management Interface"),
        (8080, "/api/admin", "Admin API"),
        (443, "/admin", "Admin Panel (HTTPS)"),
        (9090, "/", "Prometheus/Alertmanager"),
        (3000, "/", "Grafana"),
        (15672, "/", "RabbitMQ Management"),
        (8161, "/", "ActiveMQ Console"),
        (8983, "/", "Solr Admin"),
    ]

    for port, path, desc in admin_endpoints:
        if port not in ports:
            continue
        try:
            scheme = "https" if port in [443, 8443] else "http"
            resp = requests.get(
                f"{scheme}://{ip}:{port}{path}",
                timeout=3, verify=False, allow_redirects=False
            )
            if resp.status_code in [200, 301, 302]:
                # Check if it redirects to login
                has_login = False
                if resp.status_code in [301, 302]:
                    location = resp.headers.get("Location", "")
                    if "login" in location.lower() or "auth" in location.lower():
                        has_login = True
                if not has_login and resp.status_code == 200:
                    findings.append({
                        "tipo": "ADMIN_SEM_RESTRICAO",
                        "severidade": "ALTO",
                        "descricao": f"Interface admin '{desc}' acessível em {port}{path} — least privilege não aplicado",
                        "correcao": "Restringir acesso admin a rede interna/VPN. Implementar role-based access control.",
                    })
        except Exception:
            continue

    # Check for overly permissive CORS
    try:
        resp = requests.options(
            f"http://{ip}:{ports[0]}" if ports else f"http://{ip}",
            headers={"Origin": "https://evil.com"},
            timeout=3, verify=False
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil.com" in acao:
            findings.append({
                "tipo": "CORS_PERMISSIVO",
                "severidade": "ALTO",
                "descricao": "CORS Access-Control-Allow-Origin: * — qualquer origem pode acessar recursos",
                "correcao": "Restringir CORS a domínios confiáveis específicos.",
            })
    except Exception:
        pass

    return findings


def _check_lateral_movement(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica oportunidades de movimento lateral na rede."""
    findings = []

    # Services that enable lateral movement
    pivot_services = {
        22: ("SSH", "Chaves SSH compartilhadas permitem pivoting"),
        445: ("SMB", "SMB permite pass-the-hash e lateral movement"),
        135: ("RPC", "RPC permite execução remota"),
        3389: ("RDP", "RDP permite movimento lateral com credenciais"),
        5985: ("WinRM", "WinRM permite execução remota"),
        5986: ("WinRM HTTPS", "WinRM permite execução remota"),
        8080: ("HTTP Proxy", "Proxy pode ser usado para pivoting"),
        1080: ("SOCKS Proxy", "SOCKS proxy permite tunelamento"),
        3128: ("Squid Proxy", "Proxy HTTP permite pivoting"),
    }

    exposed_pivot = []
    for port, (service, risk) in pivot_services.items():
        if port in ports:
            exposed_pivot.append({"porta": port, "servico": service, "risco": risk})

    if len(exposed_pivot) >= 2:
        findings.append({
            "tipo": "LATERAL_MOVEMENT_VETORES",
            "severidade": "ALTO",
            "descricao": f"{len(exposed_pivot)} serviços que facilitam movimento lateral detectados",
            "evidencia": str(exposed_pivot[:5]),
            "correcao": "Implementar network policies que bloqueiam tráfego lateral. Usar bastion hosts.",
        })

    # Check for proxy services (tunneling risk)
    proxy_ports = [p for p in [1080, 3128, 8080, 8118, 9050] if p in ports]
    if proxy_ports:
        findings.append({
            "tipo": "PROXY_EXPOSTO",
            "severidade": "ALTO",
            "descricao": f"Serviços proxy expostos ({', '.join(str(p) for p in proxy_ports)}) — risco de tunneling",
            "correcao": "Remover ou restringir proxy services. Monitorar tráfego de saída.",
        })

    # Check for shared credentials via SSH key exposure
    if 22 in ports and shutil.which("ssh-keyscan"):
        try:
            result = subprocess.run(
                ["ssh-keyscan", "-t", "rsa,ecdsa,ed25519", ip],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                findings.append({
                    "tipo": "SSH_KEYS_EXPOSTOS",
                    "severidade": "MEDIO",
                    "descricao": "Chaves SSH do host acessíveis — verificar se são compartilhadas entre hosts",
                    "correcao": "Usar chaves SSH únicas por host. Implementar rotulação e MFA para SSH.",
                })
        except Exception:
            pass

    return findings


def _check_continuous_verification(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica mecanismos de verificação contínua (Zero Trust)."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    # Check for TLS everywhere (encryption in transit)
    non_tls_ports = [p for p in ports if p not in [443, 8443, 993, 995, 465, 5671, 8883, 636, 2636]]
    non_tls_services = {21: "FTP", 23: "Telnet", 80: "HTTP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 1433: "MSSQL"}
    exposed_non_tls = [f"{p}/{non_tls_services.get(p, 'Unknown')}" for p in non_tls_ports if p in non_tls_services]

    if exposed_non_tls:
        findings.append({
            "tipo": "SEM_TLS",
            "severidade": "ALTO",
            "descricao": f"Serviços sem TLS detectados: {', '.join(exposed_non_tls)} — tráfego interceptável",
            "correcao": "Migrar todos os serviços para TLS. Implementar mTLS para serviço-a-serviço.",
        })

    # Check for certificate-based authentication
    cert_check_ports = [p for p in [443, 8443, 636, 2636] if p in ports]
    for port in cert_check_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            # Send TLS ClientHello
            tls_hello = bytes([
                0x16, 0x03, 0x01, 0x00, 0x05,  # TLS record header
                0x01, 0x00, 0x00, 0x01, 0x03     # ClientHello
            ])
            sock.send(tls_hello)
            resp = sock.recv(256)
            sock.close()
            if resp and resp[0] == 0x16:  # TLS handshake
                findings.append({
                    "tipo": "TLS_ATIVO",
                    "severidade": "INFO",
                    "descricao": f"TLS ativo na porta {port} — verificar se exige mTLS",
                    "correcao": "Implementar mTLS (client certificates) para verificação contínua de identidade.",
                })
        except Exception:
            pass

    # Check for health check endpoints (continuous verification)
    health_paths = ["/health", "/healthz", "/ready", "/readyz", "/livez", "/api/health"]
    web_ports = [p for p in [80, 443, 8080, 8443, 3000, 9090] if p in ports]
    for port in web_ports:
        scheme = "https" if port in [443, 8443] else "http"
        for path in health_paths:
            try:
                resp = requests.get(f"{scheme}://{ip}:{port}{path}", timeout=3, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        "tipo": "HEALTH_ENDPOINT",
                        "severidade": "BAIXO",
                        "descricao": f"Health check em {path}:{port} — verificar se integra com service mesh",
                        "correcao": "Integrar health checks com service mesh para verificação contínua de confiança.",
                    })
                    break
            except Exception:
                continue

    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Valida arquitetura Zero Trust — microssegmentação, identidade, least privilege, movimento lateral, verificação contínua."""
    try:
        vulns = []
        vulns.extend(_check_microsegmentation(target, ip, ports))
        vulns.extend(_check_identity_access(target, ip, ports))
        vulns.extend(_check_least_privilege(target, ip, ports))
        vulns.extend(_check_lateral_movement(target, ip, ports))
        vulns.extend(_check_continuous_verification(target, ip, ports))

        if context:
            mesh = context.get("service_mesh", None)
            if not mesh:
                vulns.append({
                    "tipo": "SEM_SERVICE_MESH",
                    "severidade": "MEDIO",
                    "descricao": "Nenhum service mesh detectado via contexto — Zero Trust incompleto",
                    "correcao": "Implementar service mesh (Istio, Linkerd) para mTLS e observabilidade.",
                })

        return {
            "plugin": "zero_trust_validate",
            "resultados": vulns if vulns else "Arquitetura Zero Trust aparenta estar bem configurada",
        }
    except Exception as e:
        return {"plugin": "zero_trust_validate", "erro": str(e)}
