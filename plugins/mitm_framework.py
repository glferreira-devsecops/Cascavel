# plugins/mitm_framework.py — Cascavel 2026 Intelligence
import logging
import socket

import requests

logger = logging.getLogger(__name__)
# Common HTTP-only paths to test for downgrade
HTTP_PATHS = ["/", "/login", "/admin", "/api", "/index.html"]

# HSTS test paths
HSTS_PATHS = ["/", "/login", "/api", "/admin"]

# SSL stripping indicators
STRIP_INDICATORS = [
    "http://",
    "mixed-content",
    "insecure",
    "not secure",
]


def _check_arp_spoof_opportunities(target, ip):
    """Check for ARP spoofing opportunities based on network indicators."""
    findings = []
    try:
        # Check if target responds to multiple IPs (possible shared segment)
        resolved_ips = set()
        try:
            results = socket.getaddrinfo(target, None)
            for r in results:
                resolved_ips.add(r[4][0])
        except Exception as _exc:
            logger.debug("Non-critical error: %s", _exc)

        if len(resolved_ips) > 1:
            findings.append(
                {
                    "tipo": "MULTIPLE_IP_RESOLUTION",
                    "ips": list(resolved_ips),
                    "severidade": "MEDIO",
                    "descricao": "Target resolve múltiplos IPs — segmento compartilhado, ARP spoof possível",
                    "remediacao": "Implementar Dynamic ARP Inspection (DAI) e DHCP Snooping no switch.",
                }
            )

        # Check for gratuitous ARP indicators (if we can reach the host)
        findings.append(
            {
                "tipo": "ARP_SPOOF_ASSESSMENT",
                "severidade": "INFO",
                "descricao": "Segmento acessível — ARP spoofing viável se não houver proteção de switch (DAI/Port Security)",
                "remediacao": "Habilitar DAI, DHCP Snooping, Port Security. Usar 802.1X para autenticação de rede.",
                "ferramentas_teste": ["arpspoof", "bettercap", "ettercap"],
            }
        )

    except Exception as e:
        findings.append(
            {
                "tipo": "ARP_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao avaliar ARP spoofing: {str(e)}",
            }
        )
    return findings


def _check_ssl_stripping(target):
    """Check for SSL stripping vulnerability indicators."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Test if HTTP redirects to HTTPS
    try:
        resp = requests.get(f"http://{clean}/", timeout=5, allow_redirects=False, verify=False)
        if resp.status_code in [200, 301, 302]:
            location = resp.headers.get("Location", "")
            if resp.status_code == 200 and "https" not in resp.url:
                findings.append(
                    {
                        "tipo": "SSL_STRIPPING_POSSIBLE",
                        "severidade": "CRITICO",
                        "descricao": "Site serve conteúdo HTTP sem redirect para HTTPS — SSL stripping trivial",
                        "remediacao": "Implementar HSTS com includeSubDomains e preload. Redirect 301 de HTTP para HTTPS.",
                    }
                )
            elif resp.status_code in [301, 302] and "https" in location:
                findings.append(
                    {
                        "tipo": "HTTP_REDIRECT_TO_HTTPS",
                        "severidade": "MEDIO",
                        "descricao": f"HTTP redireciona para HTTPS ({resp.status_code}) — mas sem HSTS, downgrade é possível",
                        "remediacao": "Adicionar header HSTS Strict-Transport-Security com max-age mínimo de 1 ano.",
                    }
                )
            elif resp.status_code in [301, 302] and "http://" in location:
                findings.append(
                    {
                        "tipo": "HTTP_REDIRECT_TO_HTTP",
                        "severidade": "ALTO",
                        "descricao": "HTTP redireciona para outro endpoint HTTP — SSL stripping facilitado",
                        "remediacao": "Corrigir redirect para apontar sempre para HTTPS.",
                    }
                )
    except requests.ConnectionError as _exc:
        logger.debug("Non-critical error: %s", _exc)
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # Check for mixed content
    try:
        resp = requests.get(f"https://{clean}/", timeout=5, verify=False)
        if resp.status_code == 200:
            body = resp.text.lower()
            mixed_count = body.count("http://")
            if mixed_count > 0:
                findings.append(
                    {
                        "tipo": "MIXED_CONTENT",
                        "quantidade": mixed_count,
                        "severidade": "ALTO",
                        "descricao": f"{mixed_count} referências HTTP em página HTTPS — mixed content exploitable",
                        "remediacao": "Migrar todos os recursos para HTTPS. Usar protocol-relative URLs ou CSP upgrade-insecure-requests.",
                    }
                )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def _check_hsts(target):
    """Check for HSTS bypass opportunities."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    for path in HSTS_PATHS:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            hsts = resp.headers.get("Strict-Transport-Security", "")

            if not hsts:
                findings.append(
                    {
                        "tipo": "HSTS_MISSING",
                        "path": path,
                        "severidade": "ALTO",
                        "descricao": f"HSTS ausente em {path} — downgrade para HTTP trivial",
                        "remediacao": "Adicionar header Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    }
                )
            else:
                # Parse HSTS directives
                directives = {
                    d.split("=")[0].strip(): d.split("=")[1].strip() if "=" in d else "" for d in hsts.split(";")
                }
                max_age = directives.get("max-age", "0")

                if int(max_age) < 31536000:
                    findings.append(
                        {
                            "tipo": "HSTS_WEAK_MAX_AGE",
                            "max_age": max_age,
                            "path": path,
                            "severidade": "MEDIO",
                            "descricao": f"HSTS max-age={max_age} < 1 ano — proteção insuficiente",
                            "remediacao": "Aumentar max-age para 31536000 (1 ano) ou superior.",
                        }
                    )

                if "includesubdomains" not in hsts.lower():
                    findings.append(
                        {
                            "tipo": "HSTS_NO_SUBDOMAINS",
                            "path": path,
                            "severidade": "MEDIO",
                            "descricao": "HSTS sem includeSubDomains — subdomínios vulneráveis a downgrade",
                            "remediacao": "Adicionar includeSubDomains ao header HSTS.",
                        }
                    )

                if "preload" not in hsts.lower():
                    findings.append(
                        {
                            "tipo": "HSTS_NO_PRELOAD",
                            "path": path,
                            "severidade": "BAIXO",
                            "descricao": "HSTS sem preload — não protegido em primeiro acesso",
                            "remediacao": "Adicionar preload e submeter em hstspreload.org.",
                        }
                    )
            break  # Only need to check once for the main page
        except Exception as _exc:
            continue
    return findings


def _check_dns_spoof(target):
    """Check for DNS spoofing opportunities."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    try:
        # Check DNSSEC
        import subprocess

        result = subprocess.run(
            ["dig", "+short", clean, "DNSKEY"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        has_dnssec = bool(result.stdout.strip())

        if not has_dnssec:
            findings.append(
                {
                    "tipo": "NO_DNSSEC",
                    "severidade": "ALTO",
                    "descricao": "DNSSEC não configurado — DNS spoofing/cache poisoning viável",
                    "remediacao": "Implementar DNSSEC no domínio. Configurar DS records no registrador.",
                }
            )

        # Check for short TTL (cache poisoning window)
        result = subprocess.run(
            ["dig", "+ttlid", "+short", clean, "A"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if parts:
                    try:
                        ttl = int(parts[0]) if parts[0].isdigit() else None
                        if ttl and ttl < 60:
                            findings.append(
                                {
                                    "tipo": "LOW_TTL",
                                    "ttl": ttl,
                                    "severidade": "MEDIO",
                                    "descricao": f"TTL muito baixo ({ttl}s) — janela de cache poisoning expandida",
                                    "remediacao": "Aumentar TTL para 300+ segundos. Implementar DNSSEC.",
                                }
                            )
                    except (ValueError, IndexError):
                        pass

    except FileNotFoundError:
        findings.append(
            {
                "tipo": "DNS_CHECK_SKIP",
                "severidade": "INFO",
                "descricao": "dig não disponível — pular verificação DNS",
            }
        )
    except Exception as e:
        findings.append(
            {
                "tipo": "DNS_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar DNS: {str(e)}",
            }
        )

    # General DNS spoof assessment
    findings.append(
        {
            "tipo": "DNS_SPOOF_ASSESSMENT",
            "severidade": "INFO",
            "descricao": "DNS spoofing viável em rede local sem DNSSEC + com ARP spoof (ettercap/BetterCAP)",
            "remediacao": "DNSSEC + DNS-over-HTTPS (DoH) ou DNS-over-TLS (DoT). Usar resolvers DNS confiáveis.",
            "ferramentas_teste": ["ettercap", "bettercap", "dnschef", "mitmproxy"],
        }
    )

    return findings


def _check_http_downgrade(target):
    """Check for HTTP downgrade attack vectors."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Test HTTPS -> HTTP downgrade
    try:
        resp = requests.get(f"https://{clean}/", timeout=5, verify=False)
        if resp.status_code == 200:
            body = resp.text.lower()

            # Check for protocol-relative URLs (can be downgraded)
            proto_relative = body.count("//")
            if proto_relative > 2:
                findings.append(
                    {
                        "tipo": "PROTO_RELATIVE_URLS",
                        "quantidade": proto_relative,
                        "severidade": "MEDIO",
                        "descricao": f"{proto_relative} protocol-relative URLs — downgrade attack vector",
                        "remediacao": "Migrar para URLs absolutas HTTPS. Usar CSP upgrade-insecure-requests.",
                    }
                )

            # Check for HTTP resources in HTTPS page
            http_resources = body.count('src="http://') + body.count("src='http://")
            http_links = body.count('href="http://') + body.count("href='http://")
            if http_resources > 0 or http_links > 0:
                findings.append(
                    {
                        "tipo": "HTTP_RESOURCES_IN_HTTPS",
                        "recursos_http": http_resources,
                        "links_http": http_links,
                        "severidade": "ALTO",
                        "descricao": "Recursos/links HTTP dentro de página HTTPS — downgrade via MITM",
                        "remediacao": "Migrar todos os recursos para HTTPS. Implementar HSTS + CSP.",
                    }
                )

            # Check for missing security headers that prevent downgrade
            security_headers = [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Strict-Transport-Security",
            ]
            missing = [h for h in security_headers if h not in resp.headers]
            if missing:
                findings.append(
                    {
                        "tipo": "MISSING_SECURITY_HEADERS",
                        "headers_faltantes": missing,
                        "severidade": "MEDIO",
                        "descricao": f"Headers de segurança ausentes: {', '.join(missing)}",
                        "remediacao": "Implementar todos os headers de segurança recomendados via reverse proxy ou aplicação.",
                    }
                )

    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # Test for HTTP/2 downgrade
    try:
        resp = requests.get(f"https://{clean}/", timeout=5, verify=False)
        alt_svc = resp.headers.get("Alt-Svc", "")
        if alt_svc and "h2" in alt_svc:
            findings.append(
                {
                    "tipo": "HTTP2_DOWNGRADE_CHECK",
                    "severidade": "INFO",
                    "descricao": "HTTP/2 detectado — verificar se downgrade para HTTP/1.1 é restrito",
                    "remediacao": "Configurar servidor para rejeitar downgrades HTTP/2 -> HTTP/1.1 quando não suportado.",
                }
            )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    MITM Framework 2026-Grade — ARP, SSL Stripping, HSTS, DNS Spoof, HTTP Downgrade.

    Técnicas: ARP spoofing opportunity assessment, SSL stripping detection,
    HSTS analysis (missing/weak/no-subdomains/no-preload), DNS spoofing
    (DNSSEC/TTL/cache poisoning), HTTP downgrade vectors (mixed content,
    protocol-relative URLs, missing security headers).
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "arp_spoof": [],
        "ssl_stripping": [],
        "hsts_bypass": [],
        "dns_spoof": [],
        "http_downgrade": [],
    }

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    resultado["arp_spoof"] = _check_arp_spoof_opportunities(clean_target, ip)
    resultado["ssl_stripping"] = _check_ssl_stripping(clean_target)
    resultado["hsts_bypass"] = _check_hsts(clean_target)
    resultado["dns_spoof"] = _check_dns_spoof(clean_target)
    resultado["http_downgrade"] = _check_http_downgrade(clean_target)

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )
    alto = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "ALTO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "altos": alto,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if alto > 0 else "LIMPO"),
    }

    return {
        "plugin": "mitm_framework",
        "versao": "2026.1",
        "tecnicas": [
            "arp_spoof_assessment",
            "ssl_stripping",
            "hsts_analysis",
            "dns_spoof_check",
            "http_downgrade_vectors",
        ],
        "resultados": resultado,
    }
