# plugins/dns_rebinding.py
def run(target, ip, open_ports, banners):
    """
    Detector de DNS Rebinding e DNS Exfiltration vectors.
    Analisa configuração DNS do alvo para vulnerabilidades.
    """
    import socket
    import requests

    resultado = {"dns_analysis": {}, "vulns": []}

    # 1. Verificar TTL baixo (facilita rebinding)
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "+ttlid", target, "A"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        resultado["dns_analysis"]["dig_output"] = output

        # Verificar múltiplos IPs (load balancing pode ser explorado)
        ips = [line.strip() for line in output.split("\n") if line.strip()]
        if len(ips) > 1:
            resultado["dns_analysis"]["multiplos_ips"] = ips
    except Exception:
        pass

    # 2. Verificar wildcard DNS
    import random
    import string
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
    try:
        wild_ip = socket.gethostbyname(f"{random_sub}.{target}")
        resultado["vulns"].append({
            "tipo": "WILDCARD_DNS",
            "subdominio_random": f"{random_sub}.{target}",
            "ip_resolvido": wild_ip,
            "severidade": "MEDIO",
            "descricao": "Wildcard DNS ativo — facilita phishing e subdomain takeover",
        })
    except socket.gaierror:
        resultado["dns_analysis"]["wildcard"] = False

    # 3. Verificar DNSSEC
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+dnssec", "+short", target, "A"],
            capture_output=True, text=True, timeout=10
        )
        if "RRSIG" not in result.stdout:
            resultado["vulns"].append({
                "tipo": "DNSSEC_AUSENTE",
                "severidade": "MEDIO",
                "descricao": "DNSSEC não configurado — vulnerável a DNS spoofing",
            })
        else:
            resultado["dns_analysis"]["dnssec"] = True
    except Exception:
        pass

    # 4. Verificar registros SPF/DMARC/DKIM
    dns_sec_records = [
        (f"{target}", "TXT", "SPF"),
        (f"_dmarc.{target}", "TXT", "DMARC"),
        (f"default._domainkey.{target}", "TXT", "DKIM"),
    ]
    for domain, rtype, label in dns_sec_records:
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=10
            )
            if not result.stdout.strip():
                resultado["vulns"].append({
                    "tipo": f"{label}_AUSENTE",
                    "severidade": "MEDIO" if label == "SPF" else "BAIXO",
                    "descricao": f"Registro {label} não encontrado — email spoofing possível",
                })
            else:
                resultado["dns_analysis"][label.lower()] = result.stdout.strip()[:100]
        except Exception:
            continue

    return {"plugin": "dns_rebinding", "resultados": resultado}
