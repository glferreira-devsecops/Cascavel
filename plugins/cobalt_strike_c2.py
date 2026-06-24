"""
[+] Plugin: Cobalt Strike & C2 Framework Detection
[+] Description: Detecta indicadores de frameworks C2 (Cobalt Strike, Sliver, Empire, Metasploit)
[+] Category: Post-Exploitation / C2 Detection
[+] CVSS: 9.0 (Critical)
[+] Author: CASCAVEL Framework
"""

import re
import socket
from typing import Any

# Known C2 default ports
C2_PORTS = {
    50050: "Cobalt Strike TeamServer",
    443: "Cobalt Strike HTTPS Beacon",
    80: "Cobalt Strike HTTP Beacon",
    8080: "Cobalt Strike Alternative",
    31337: "Sliver C2 Default",
    8443: "Sliver C2 mTLS",
    8888: "Empire Listener",
    1337: "Empire Alternative",
    4444: "Metasploit Handler Default",
    4445: "Metasploit Handler Alt",
    5555: "Metasploit Handler Alt",
}

# Cobalt Strike watermark patterns (known leaked watermarks)
COBALT_WATERMARKS = [
    "135959331",   # Well-known leaked watermark
    "000000000",   # Null watermark (cracked)
    "100000000",   # Common cracked watermark
    "1580108089",  # Another known leaked
]

# Known C2 JA3/JA3S fingerprints (Cobalt Strike default malleable)
C2_JA3_INDICATORS = [
    "72a589da586844d7f0818ce684948eea",  # Cobalt Strike default
    "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike variant
]

# Known C2 User-Agent strings
C2_USER_AGENTS = [
    r"Mozilla/4\.0 \(compatible; MSIE 8\.0; Windows NT 6\.1;",
    r"Mozilla/5\.0 \(Windows; U; MSIE 7\.0; Windows NT 5\.2\)",
    r"Mozilla/5\.0 \(compatible; MSIE 10\.0; Windows NT 6\.2;",
    r"Mozilla/5\.0 \(Windows NT 6\.1; WOW64; Trident/7\.0; rv:11\.0\) like Gecko",
]

# Known C2 domains (suspicious patterns)
C2_DOMAIN_PATTERNS = [
    r".*\.(top|xyz|tk|ml|ga|cf|buzz|icu)$",  # Suspicious TLDs
    r"^[a-z0-9]{12,}\..*",                    # Long random subdomains
    r".*\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\..*", # IP-like subdomains
]


def _check_port_banners(ip: str, ports: list[int], banners: dict[str, str]) -> list[dict[str, Any]]:
    """Analisa banners em portas conhecidas de C2."""
    findings = []
    for port, service in C2_PORTS.items():
        if port in ports:
            banner = banners.get(str(port), "")
            # Cobalt Strike beacon patterns
            if any(kw in banner.lower() for kw in ["cobalt", "beacon", "sleep", "jitter"]):
                findings.append({
                    "tipo": "COBALT_STRIKE_BANNER",
                    "severidade": "CRITICO",
                    "descricao": f"Banner suspeito de Cobalt Strike na porta {port}",
                    "evidencia": banner[:200],
                    "correcao": "Investigar processo associado a esta porta. Verificar memory dump para confirmar beacon.",
                })
            # Sliver C2 patterns
            if any(kw in banner.lower() for kw in ["sliver", "implant", "session"]):
                findings.append({
                    "tipo": "SLIVER_C2_BANNER",
                    "severidade": "CRITICO",
                    "descricao": f"Banner suspeito de Sliver C2 na porta {port}",
                    "evidencia": banner[:200],
                    "correcao": "Isolar host e analisar tráfego de rede para confirmar C2.",
                })
            # Generic suspicious on known C2 port
            if port in [50050, 31337, 1337] and port in ports:
                findings.append({
                    "tipo": "C2_PORT_SUSPEITA",
                    "severidade": "ALTO",
                    "descricao": f"Porta {port} ({service}) aberta — frequente uso em ataques C2",
                    "evidencia": f"Porta aberta, banner: {banner[:100]}" if banner else "Porta aberta sem banner",
                    "correcao": "Verificar se o serviço na porta é legítimo. Bloquear se não autorizado.",
                })
    return findings


def _check_cobalt_watermark(target: str) -> list[dict[str, Any]]:
    """Verifica se o alvo responde com padrões de watermark do Cobalt Strike."""
    findings = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, 50050))
        data = sock.recv(1024)
        sock.close()
        raw = data.hex() if data else ""
        for wm in COBALT_WATERMARKS:
            wm_hex = wm.encode().hex()
            if wm_hex in raw:
                findings.append({
                    "tipo": "COBALT_WATERMARK",
                    "severidade": "CRITICO",
                    "descricao": f"Watermark do Cobalt Strike detectado ({wm})",
                    "evidencia": f"Hex data: {raw[:100]}",
                    "correcao": "Watermark cracked/leaked indica versão pirateada. Rastrear infraestrutura do atacante.",
                })
    except (TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    return findings


def _check_beacon_config_patterns(banners: dict[str, str]) -> list[dict[str, Any]]:
    """Analisa padrões de configuração de beacon em banners coletados."""
    findings = []
    beacon_patterns = [
        (r"sleep\s+\d+", "Sleep command pattern"),
        (r"jitter\s+\d+", "Jitter configuration"),
        (r"beacon\s+http", "Beacon HTTP mode"),
        (r"beacon\s+dns", "Beacon DNS mode"),
        (r"spawn\s+[a-z]:", "Spawn process injection"),
        (r"inject\s+\d+", "Process injection command"),
        (r"malleable[_\s]?c2", "Malleable C2 profile"),
    ]
    for port_str, banner in banners.items():
        if not banner:
            continue
        for pattern, desc in beacon_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                findings.append({
                    "tipo": "BEACON_CONFIG_PATTERN",
                    "severidade": "CRITICO",
                    "descricao": f"Padrão de beacon detectado: {desc}",
                    "porta": port_str,
                    "evidencia": banner[:200],
                    "correcao": "Realizar memory dump do processo suspeito e analisar com memory forensics.",
                })
    return findings


def _check_dns_beacon(target: str) -> list[dict[str, Any]]:
    """Verifica padrões de DNS beacon (Cobalt Strike DNS mode)."""
    findings = []
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", target],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        # Check for high-entropy DNS responses (common in DNS beacons)
        if output and re.match(r"^[a-zA-Z0-9+/=]{20,}$", output.split("\n")[0]):
            findings.append({
                "tipo": "DNS_BEACON_SUSPEITO",
                "severidade": "ALTO",
                "descricao": "Resposta DNS com alta entropia — possivel DNS beacon C2",
                "evidencia": output[:200],
                "correcao": "Analisar tráfego DNS para identificar padrões de beaconing. Verificar se há encoded C2.",
            })
    except Exception:
        pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Detecta indicadores de frameworks C2 em uso no alvo."""
    try:
        vulns = []
        vulns.extend(_check_port_banners(ip, ports, banners))
        vulns.extend(_check_cobalt_watermark(ip))
        vulns.extend(_check_beacon_config_patterns(banners))
        vulns.extend(_check_dns_beacon(target))

        # Context enrichment
        if context:
            extra_indicators = context.get("c2_indicators", [])
            if extra_indicators:
                vulns.append({
                    "tipo": "CONTEXT_C2_INDICATORS",
                    "severidade": "ALTO",
                    "descricao": f"Indicadores C2 adicionais via contexto: {len(extra_indicators)} encontrado(s)",
                    "correcao": "Correlacionar com threat intelligence feeds.",
                })

        return {
            "plugin": "cobalt_strike_c2",
            "resultados": vulns if vulns else "Nenhum indicador de framework C2 detectado",
        }
    except Exception as e:
        return {"plugin": "cobalt_strike_c2", "erro": str(e)}
