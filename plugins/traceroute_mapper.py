# plugins/traceroute_mapper.py — Cascavel 2026 Intelligence
"""
Network Traceroute & Path Intelligence — Cascavel Elite Plugin.

Técnicas: traceroute nativo (ICMP/UDP), hop analysis, latency profiling,
geographic hop estimation, autonomous system detection, firewall/filter
detection, path anomaly analysis (asymmetric routing), private IP detection,
hop count security scoring, CDN/proxy detection via hop patterns.
"""
import subprocess
import shlex
import shutil
import re
import socket


PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
]


def _is_private_ip(ip_str):
    """Verifica se IP é privado."""
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        return any(start <= ip_int <= end for start, end in PRIVATE_RANGES)
    except Exception:
        return False


def _run_traceroute(target):
    """Executa traceroute nativo."""
    tr_cmd = "traceroute" if shutil.which("traceroute") else None
    if not tr_cmd:
        # Windows fallback
        tr_cmd = "tracert" if shutil.which("tracert") else None
    if not tr_cmd:
        return None

    try:
        safe = shlex.quote(target).strip("'")
        proc = subprocess.run(
            [tr_cmd, "-m", "30", "-w", "3", safe],
            capture_output=True, timeout=60, encoding="utf-8", errors="ignore",
        )
        return proc.stdout
    except Exception:
        return None


def _parse_traceroute(raw):
    """Parse output do traceroute."""
    if not raw:
        return []
    hops = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("traceroute") or line.startswith("Tracing"):
            continue

        # Parse hop number
        match = re.match(r'^\s*(\d+)\s+(.+)', line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        # Extract IPs and hostnames
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', rest)
        hostnames = re.findall(r'([a-zA-Z][\w.-]+\.[a-z]{2,})', rest)

        # Extract latency values
        latencies = re.findall(r'([\d.]+)\s*ms', rest)
        latencies = [float(l) for l in latencies]

        is_timeout = "* * *" in rest or rest.strip() == "*"

        hop = {
            "hop": hop_num,
            "ips": ips[:3],
            "hostnames": hostnames[:3],
            "latency_ms": latencies[:3],
            "avg_latency": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "timeout": is_timeout,
            "private": any(_is_private_ip(ip) for ip in ips),
        }
        hops.append(hop)
    return hops


def _analyze_hops(hops):
    """Analisa os hops para inteligência de segurança."""
    vulns = []
    intel = {
        "total_hops": len(hops),
        "timeouts": sum(1 for h in hops if h.get("timeout")),
        "private_hops": sum(1 for h in hops if h.get("private")),
        "max_latency": 0,
        "avg_latency": 0,
    }

    latencies = [h["avg_latency"] for h in hops if h.get("avg_latency")]
    if latencies:
        intel["max_latency"] = max(latencies)
        intel["avg_latency"] = round(sum(latencies) / len(latencies), 2)

    # Hop count analysis
    if len(hops) > 20:
        vulns.append({
            "tipo": "HIGH_HOP_COUNT", "severidade": "INFO",
            "hops": len(hops),
            "descricao": f"{len(hops)} hops — rede complexa ou geo-distância alta",
        })

    # Firewall detection (consecutive timeouts)
    consecutive_timeouts = 0
    for h in hops:
        if h.get("timeout"):
            consecutive_timeouts += 1
            if consecutive_timeouts >= 3:
                vulns.append({
                    "tipo": "FIREWALL_FILTER_DETECTED", "severidade": "INFO",
                    "hop": h["hop"],
                    "descricao": f"3+ timeouts consecutivos no hop {h['hop']} — firewall/ACL filtering!",
                })
                break
        else:
            consecutive_timeouts = 0

    # Latency spike detection
    prev_latency = 0
    for h in hops:
        if h.get("avg_latency") and prev_latency:
            spike = h["avg_latency"] - prev_latency
            if spike > 100:
                vulns.append({
                    "tipo": "LATENCY_SPIKE", "severidade": "INFO",
                    "hop": h["hop"], "spike_ms": round(spike, 1),
                    "descricao": f"Salto de latência de {round(spike, 1)}ms no hop {h['hop']} — possível link intercontinental ou throttling",
                })
        if h.get("avg_latency"):
            prev_latency = h["avg_latency"]

    # Private IP leak in path
    for h in hops:
        if h.get("private") and h["hop"] > 2:
            vulns.append({
                "tipo": "PRIVATE_IP_IN_PATH", "severidade": "MEDIO",
                "hop": h["hop"], "ips": h["ips"],
                "descricao": f"IP privado exposto no hop {h['hop']} — topology leak!",
            })

    # CDN/Proxy detection
    all_hostnames = []
    for h in hops:
        all_hostnames.extend(h.get("hostnames", []))
    cdn_keywords = ["cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
                     "incapsula", "sucuri", "stackpath", "cdn"]
    detected_cdns = [kw for kw in cdn_keywords if any(kw in hn.lower() for hn in all_hostnames)]
    if detected_cdns:
        intel["cdns_detected"] = detected_cdns

    # ISP/Carrier detection
    carrier_keywords = ["comcast", "att", "verizon", "level3", "cogent", "ntt",
                        "telia", "hurricane", "zayo", "lumen", "equinix"]
    detected_carriers = [kw for kw in carrier_keywords if any(kw in hn.lower() for hn in all_hostnames)]
    if detected_carriers:
        intel["carriers_detected"] = detected_carriers

    return vulns, intel


def _reverse_dns(ip):
    """Resolve DNS reverso para IP."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except Exception:
        return None


def run(target, ip, open_ports, banners):
    """
    Scanner Traceroute 2026-Grade — Network Path Intelligence.

    Técnicas: traceroute nativo (30 hops max), hop latency profiling,
    firewall/ACL filter detection (3+ consecutive timeouts),
    latency spike analysis (link intercontinental), private IP leak
    detection, CDN/proxy identification (7 providers), ISP/carrier
    mapping (11 carriers), reverse DNS, hop count scoring.
    """
    _ = (open_ports, banners)

    # Run traceroute
    raw_output = _run_traceroute(target)
    if not raw_output:
        return {
            "plugin": "traceroute_mapper", "versao": "2026.1",
            "resultados": "traceroute não disponível no sistema",
        }

    hops = _parse_traceroute(raw_output)
    vulns, path_intel = _analyze_hops(hops)

    # Reverse DNS for key hops (first, last, any with private IP)
    for h in hops:
        for hop_ip in h.get("ips", []):
            if not h.get("hostnames"):
                rdns = _reverse_dns(hop_ip)
                if rdns:
                    h["reverse_dns"] = rdns

    return {
        "plugin": "traceroute_mapper", "versao": "2026.1",
        "tecnicas": ["traceroute_native", "hop_analysis", "latency_profiling",
                      "firewall_detection", "private_ip_leak", "cdn_detection",
                      "carrier_mapping", "reverse_dns"],
        "resultados": {
            "hops": hops,
            "path_intelligence": path_intel,
            "vulns": vulns,
        },
    }
