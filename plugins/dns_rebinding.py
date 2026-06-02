# plugins/dns_rebinding.py — Cascavel 2026 Intelligence
import random
import shlex
import socket
import string
import subprocess


def run(target, ip, open_ports, banners):
    """
    Scanner DNS Rebinding & Security 2026-Grade.

    Técnicas: TTL analysis (low TTL = rebinding vector), wildcard DNS detection,
    DNSSEC validation, SPF/DMARC/DKIM email security, DNS zone transfer attempt,
    0.0.0.0 rebinding test, multiple A record detection, CAA record check,
    NS record analysis, MX backup analysis.
    """
    _ = (ip, open_ports, banners)
    resultado = {"dns_analysis": {}, "vulns": []}

    # 1. TTL analysis (low TTL facilitates rebinding)
    _check_ttl(target, resultado)

    # 2. Wildcard DNS
    _check_wildcard(target, resultado)

    # 3. Multiple A records (round-robin — rebinding vector)
    _check_multiple_a(target, resultado)

    # 4. DNSSEC
    _check_dnssec(target, resultado)

    # 5. SPF/DMARC/DKIM
    _check_email_security(target, resultado)

    # 6. Zone transfer
    _check_zone_transfer(target, resultado)

    # 7. CAA records
    _check_caa(target, resultado)

    # 8. NS analysis
    _check_ns_records(target, resultado)

    # 9. 0.0.0.0 rebinding test
    _check_zero_ip_rebinding(target, resultado)

    return {
        "plugin": "dns_rebinding",
        "versao": "2026.1",
        "tecnicas": [
            "ttl_analysis",
            "wildcard_dns",
            "multiple_a",
            "dnssec",
            "email_security",
            "zone_transfer",
            "caa_records",
            "ns_analysis",
            "zero_ip_rebinding",
        ],
        "resultados": resultado,
    }


def _run_dig(args):
    """Executa dig com args e retorna stdout."""
    try:
        cmd = ["dig"] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""


def _check_ttl(target, resultado):
    """Analisa TTL dos registros DNS."""
    output = _run_dig(["+noall", "+answer", shlex.quote(target), "A"])
    resultado["dns_analysis"]["dig_a"] = output[:200]

    if output:
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ttl = int(parts[1])
                    resultado["dns_analysis"]["ttl"] = ttl
                    if ttl <= 60:
                        resultado["vulns"].append(
                            {
                                "tipo": "DNS_LOW_TTL",
                                "ttl": ttl,
                                "severidade": "ALTO",
                                "descricao": f"TTL muito baixo ({ttl}s) — facilita DNS rebinding attack!",
                            }
                        )
                    elif ttl <= 300:
                        resultado["vulns"].append(
                            {
                                "tipo": "DNS_SHORT_TTL",
                                "ttl": ttl,
                                "severidade": "MEDIO",
                                "descricao": f"TTL curto ({ttl}s) — possível vetor de DNS rebinding",
                            }
                        )
                    break
                except ValueError:
                    continue


def _check_wildcard(target, resultado):
    """Verifica wildcard DNS."""
    random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
    try:
        wild_ip = socket.gethostbyname(f"{random_sub}.{target}")
        resultado["vulns"].append(
            {
                "tipo": "WILDCARD_DNS",
                "subdominio_random": f"{random_sub}.{target}",
                "ip_resolvido": wild_ip,
                "severidade": "MEDIO",
                "descricao": "Wildcard DNS — facilita phishing e subdomain takeover",
            }
        )
    except socket.gaierror:
        resultado["dns_analysis"]["wildcard"] = False


def _check_multiple_a(target, resultado):
    """Verifica múltiplos registros A (round-robin)."""
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        unique_ips = list(set(addr[4][0] for addr in ips))
        resultado["dns_analysis"]["a_records"] = unique_ips
        if len(unique_ips) > 1:
            # Check for internal IPs
            internal = [
                ip for ip in unique_ips if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")
            ]
            if internal:
                resultado["vulns"].append(
                    {
                        "tipo": "DNS_INTERNAL_IP_LEAK",
                        "ips_internos": internal,
                        "severidade": "ALTO",
                        "descricao": "Registro A contém IP interno — information leak!",
                    }
                )
    except Exception:
        pass


def _check_dnssec(target, resultado):
    """Verifica configuração DNSSEC."""
    output = _run_dig(["+dnssec", "+short", shlex.quote(target), "A"])
    if "RRSIG" not in output:
        resultado["vulns"].append(
            {
                "tipo": "DNSSEC_AUSENTE",
                "severidade": "MEDIO",
                "descricao": "DNSSEC não configurado — vulnerável a DNS spoofing/poisoning",
            }
        )
    else:
        resultado["dns_analysis"]["dnssec"] = True


def _check_email_security(target, resultado):
    """Verifica SPF, DMARC e DKIM."""
    dns_sec_records = [
        (shlex.quote(target), "TXT", "SPF", "v=spf1"),
        (shlex.quote(f"_dmarc.{target}"), "TXT", "DMARC", "v=DMARC1"),
        (shlex.quote(f"default._domainkey.{target}"), "TXT", "DKIM", "v=DKIM1"),
    ]
    for domain, rtype, label, expected in dns_sec_records:
        output = _run_dig(["+short", domain, rtype])
        if not output or expected not in output:
            sev = "ALTO" if label == "DMARC" else "MEDIO"
            resultado["vulns"].append(
                {
                    "tipo": f"{label}_AUSENTE",
                    "severidade": sev,
                    "descricao": f"Registro {label} não encontrado — email spoofing possível!",
                }
            )
        else:
            resultado["dns_analysis"][label.lower()] = output[:100]
            # Check for SPF ~all (softfail)
            if label == "SPF" and "~all" in output:
                resultado["vulns"].append(
                    {
                        "tipo": "SPF_SOFTFAIL",
                        "severidade": "MEDIO",
                        "descricao": "SPF com ~all (softfail) — emails spoofados podem ser entregues!",
                    }
                )
            if label == "SPF" and "+all" in output:
                resultado["vulns"].append(
                    {
                        "tipo": "SPF_ALLOW_ALL",
                        "severidade": "CRITICO",
                        "descricao": "SPF com +all — qualquer servidor pode enviar email como este domínio!",
                    }
                )


def _check_zone_transfer(target, resultado):
    """Tenta zone transfer (AXFR)."""
    ns_output = _run_dig(["+short", shlex.quote(target), "NS"])
    if not ns_output:
        return

    for ns in ns_output.split("\n")[:3]:
        ns = ns.strip().rstrip(".")
        if not ns:
            continue
        output = _run_dig(["@" + shlex.quote(ns), shlex.quote(target), "AXFR", "+short"])
        if output and len(output) > 50:
            resultado["vulns"].append(
                {
                    "tipo": "DNS_ZONE_TRANSFER",
                    "ns": ns,
                    "severidade": "CRITICO",
                    "descricao": f"Zone transfer (AXFR) permitido em {ns} — full DNS exposure!",
                    "amostra": output[:300],
                }
            )
            break


def _check_caa(target, resultado):
    """Verifica registros CAA (Certificate Authority Authorization)."""
    output = _run_dig(["+short", shlex.quote(target), "CAA"])
    if not output:
        resultado["vulns"].append(
            {
                "tipo": "CAA_AUSENTE",
                "severidade": "BAIXO",
                "descricao": "Registros CAA ausentes — qualquer CA pode emitir certificados!",
            }
        )
    else:
        resultado["dns_analysis"]["caa"] = output[:100]


def _check_ns_records(target, resultado):
    """Analisa NS records para detectar problemas."""
    output = _run_dig(["+short", shlex.quote(target), "NS"])
    if output:
        ns_servers = [ns.strip().rstrip(".") for ns in output.split("\n") if ns.strip()]
        resultado["dns_analysis"]["ns_servers"] = ns_servers

        if len(ns_servers) < 2:
            resultado["vulns"].append(
                {
                    "tipo": "DNS_SINGLE_NS",
                    "severidade": "MEDIO",
                    "descricao": "Apenas 1 NS server — single point of failure!",
                }
            )


def _check_zero_ip_rebinding(target, resultado):
    """Testa se o domínio resolve para 0.0.0.0 (rebinding vector)."""
    try:
        ip = socket.gethostbyname(target)
        if ip == "0.0.0.0":
            resultado["vulns"].append(
                {
                    "tipo": "DNS_ZERO_IP",
                    "severidade": "CRITICO",
                    "descricao": "Domínio resolve para 0.0.0.0 — DNS rebinding bypass!",
                }
            )
        elif ip.startswith("127."):
            resultado["vulns"].append(
                {
                    "tipo": "DNS_LOCALHOST_RESOLVE",
                    "ip": ip,
                    "severidade": "ALTO",
                    "descricao": f"Domínio resolve para {ip} — possível DNS rebinding!",
                }
            )
    except Exception:
        pass
