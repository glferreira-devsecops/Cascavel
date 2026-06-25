# plugins/dns_recon_deep.py — Cascavel 2026 Intelligence
import logging
import socket
import subprocess

logger = logging.getLogger(__name__)
# Subdomain wordlist (top entries)
SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "proxy",
    "vpn",
    "gateway",
    "router",
    "admin",
    "administrator",
    "webdisk",
    "cpanel",
    "whm",
    "webhost",
    "api",
    "api2",
    "api3",
    "dev",
    "dev2",
    "development",
    "staging",
    "stage",
    "test",
    "testing",
    "sandbox",
    "qa",
    "uat",
    "demo",
    "preview",
    "beta",
    "alpha",
    "canary",
    "nightly",
    "rc",
    "pre",
    "app",
    "app2",
    "application",
    "portal",
    "dashboard",
    "panel",
    "console",
    "db",
    "database",
    "mysql",
    "postgres",
    "postgresql",
    "mongo",
    "mongodb",
    "redis",
    "elasticsearch",
    "elastic",
    "search",
    "solr",
    "cache",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "files",
    "uploads",
    "download",
    "downloads",
    "docs",
    "doc",
    "documentation",
    "wiki",
    "help",
    "support",
    "kb",
    "knowledge",
    "faq",
    "forum",
    "community",
    "blog",
    "news",
    "press",
    "status",
    "monitor",
    "monitoring",
    "grafana",
    "prometheus",
    "kibana",
    "log",
    "logs",
    "logging",
    "sentry",
    "ci",
    "cd",
    "jenkins",
    "gitlab",
    "github",
    "bitbucket",
    "git",
    "svn",
    "build",
    "deploy",
    "release",
    "artifacts",
    "registry",
    "docker",
    "k8s",
    "kubernetes",
    "kube",
    "rancher",
    "openshift",
    "mesos",
    "shop",
    "store",
    "ecommerce",
    "cart",
    "checkout",
    "payment",
    "billing",
    "invoice",
    "account",
    "my",
    "login",
    "signin",
    "auth",
    "sso",
    "oauth",
    "ldap",
    "ad",
    "directory",
    "iam",
    "identity",
    "internal",
    "intranet",
    "extranet",
    "private",
    "corp",
    "corporate",
    "office",
    "outlook",
    "exchange",
    "owa",
    "autodiscover",
    "mx",
    "backup",
    "bak",
    "old",
    "legacy",
    "archive",
    "mirror",
    "replica",
    "mobile",
    "m",
    "wap",
    "touch",
    "responsive",
    "analytics",
    "stats",
    "statistics",
    "report",
    "reports",
    "reporting",
    "crm",
    "erp",
    "hr",
    "finance",
    "accounting",
    "payroll",
    "iot",
    "edge",
    "node",
    "worker",
    "job",
    "jobs",
    "queue",
    "mq",
    "rabbit",
    "kafka",
    "stream",
    "events",
    "webhook",
    "callback",
    "notify",
    "chat",
    "im",
    "messaging",
    "sms",
    "voice",
    "voip",
    "sip",
    "telecom",
    "map",
    "maps",
    "geo",
    "location",
    "weather",
    "social",
    "media",
    "feed",
    "rss",
    "atom",
    "game",
    "gaming",
    "play",
    "match",
    "ai",
    "ml",
    "data",
    "bigdata",
    "hadoop",
    "spark",
    "pipeline",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "alibaba",
    "heroku",
    "vercel",
    "netlify",
    "video",
    "stream",
    "live",
    "tv",
    "radio",
    "podcast",
    "go",
    "link",
    "redirect",
    "short",
    "url",
]


def _test_zone_transfer(target):
    """Test DNS zone transfer (AXFR) vulnerability."""
    findings = []
    nameservers = []

    # Get nameservers
    try:
        result = subprocess.run(
            ["dig", "+short", target, "NS"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        nameservers = [ns.strip().rstrip(".") for ns in result.stdout.splitlines() if ns.strip()]
    except FileNotFoundError:
        findings.append(
            {
                "tipo": "ZONE_TRANSFER_SKIP",
                "severidade": "INFO",
                "descricao": "dig não disponível — pular teste de zone transfer",
            }
        )
        return findings
    except Exception as e:
        findings.append(
            {
                "tipo": "ZONE_TRANSFER_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao obter NS: {str(e)}",
            }
        )
        return findings

    for ns in nameservers:
        try:
            # Resolve NS hostname
            try:
                ns_ip = socket.gethostbyname(ns)
            except socket.gaierror:
                continue

            # Attempt zone transfer
            result = subprocess.run(
                ["dig", f"@{ns_ip}", target, "AXFR"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout

            if "XFR size" in output or ("IN\tA" in output and output.count("IN\tA") > 5):
                # Zone transfer successful
                records = [line for line in output.splitlines() if "IN\t" in line and not line.startswith(";")]
                findings.append(
                    {
                        "tipo": "ZONE_TRANSFER_SUCCESS",
                        "nameserver": ns,
                        "ns_ip": ns_ip,
                        "records_expostos": len(records),
                        "amostra": records[:20],
                        "severidade": "CRITICO",
                        "descricao": f"Zone transfer (AXFR) permitido no NS {ns} — {len(records)} registros expostos",
                        "remediacao": "Restringir zone transfer apenas a IPs autorizados (slave servers). Configurar TSIG.",
                    }
                )
            elif "Transfer failed" not in output and "connection timed out" not in output.lower():
                findings.append(
                    {
                        "tipo": "ZONE_TRANSFER_PARTIAL",
                        "nameserver": ns,
                        "ns_ip": ns_ip,
                        "severidade": "ALTO",
                        "descricao": f"Zone transfer parcial ou resposta suspeita do NS {ns}",
                        "remediacao": "Verificar configuração do BIND/NSD. Restringir AXFR.",
                    }
                )
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            findings.append(
                {
                    "tipo": "ZONE_TRANSFER_ERROR",
                    "nameserver": ns,
                    "severidade": "INFO",
                    "descricao": f"Erro ao testar zone transfer em {ns}: {str(e)}",
                }
            )

    if not nameservers:
        findings.append(
            {
                "tipo": "NO_NAMESERVERS",
                "severidade": "INFO",
                "descricao": "Nenhum nameserver encontrado para teste de zone transfer",
            }
        )

    return findings


def _test_cache_poisoning(target):
    """Test for DNS cache poisoning susceptibility."""
    findings = []

    # Check DNSSEC
    try:
        result = subprocess.run(
            ["dig", "+short", target, "DNSKEY"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        has_dnskey = bool(result.stdout.strip())

        result_ds = subprocess.run(
            ["dig", "+short", target, "DS"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        has_ds = bool(result_ds.stdout.strip())

        if not has_dnskey and not has_ds:
            findings.append(
                {
                    "tipo": "NO_DNSSEC",
                    "severidade": "ALTO",
                    "descricao": "DNSSEC não configurado — DNS cache poisoning viável (Kaminsky attack)",
                    "remediacao": "Implementar DNSSEC. Configurar DS records no registrador e assinar zona.",
                }
            )
        elif has_dnskey:
            findings.append(
                {
                    "tipo": "DNSSEC_ACTIVE",
                    "severidade": "INFO",
                    "descricao": "DNSSEC configurado — proteção contra cache poisoning ativa",
                }
            )
    except FileNotFoundError:
        pass
    except Exception as e:
        findings.append(
            {
                "tipo": "DNSSEC_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar DNSSEC: {str(e)}",
            }
        )

    # Check source port randomization
    try:
        for i in range(3):
            result = subprocess.run(
                ["dig", "+short", f"test{i}.cascavel-check.internal", f"@{target}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        findings.append(
            {
                "tipo": "SOURCE_PORT_CHECK",
                "severidade": "INFO",
                "descricao": "Verificar source port randomization com ferramentas especializadas (dns-oarc.net/porttest)",
                "remediacao": "Usar BIND 9.5+ ou equivalente com source port randomization habilitado.",
            }
        )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # Check TTL values
    try:
        result = subprocess.run(
            ["dig", "+ttlid", "+noall", "+answer", target, "A"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if parts:
                    try:
                        ttl = int(parts[-2]) if parts[-2].isdigit() else None
                        if ttl and ttl < 60:
                            findings.append(
                                {
                                    "tipo": "LOW_TTL",
                                    "ttl": ttl,
                                    "severidade": "MEDIO",
                                    "descricao": f"TTL muito baixo ({ttl}s) — janela de cache poisoning expandida",
                                    "remediacao": "Aumentar TTL para 300+ segundos. DNSSEC protege mesmo com TTL baixo.",
                                }
                            )
                    except (ValueError, IndexError):
                        pass
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    return findings


def _test_dns_rebinding(target):
    """Test for DNS rebinding vulnerability."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # Check for split-horizon DNS indicators
    try:
        internal_result = subprocess.run(
            ["dig", "+short", clean, "A"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ips = [ip.strip() for ip in internal_result.stdout.splitlines() if ip.strip()]

        # Check if any resolved IP is private
        private_ips = []
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                if (
                    parts[0] == "10"
                    or (parts[0] == "172" and 16 <= int(parts[1]) <= 31)
                    or (parts[0] == "192" and parts[1] == "168")
                ):
                    private_ips.append(ip)

        if private_ips:
            findings.append(
                {
                    "tipo": "PRIVATE_IP_RESOLVED",
                    "ips": private_ips,
                    "severidade": "MEDIO",
                    "descricao": f"Domínio resolve para IP privado: {', '.join(private_ips)} — DNS rebinding possível",
                    "remediacao": "Validar Host header server-side. Usar CSP. Bloquear respostas DNS para RFC1918.",
                }
            )

        # Check for wildcard DNS
        import random
        import string

        random_sub = "".join(random.choices(string.ascii_lowercase, k=20))
        wildcard_result = subprocess.run(
            ["dig", "+short", f"{random_sub}.{clean}", "A"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if wildcard_result.stdout.strip():
            findings.append(
                {
                    "tipo": "WILDCARD_DNS",
                    "ip": wildcard_result.stdout.strip(),
                    "severidade": "MEDIO",
                    "descricao": "Wildcard DNS configurado — rebinding attack vector",
                    "remediacao": "Desabilitar wildcard DNS se não necessário. Validar Host header.",
                }
            )

    except Exception as e:
        findings.append(
            {
                "tipo": "REBINDING_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao verificar DNS rebinding: {str(e)}",
            }
        )

    return findings


def _test_dns_tunneling(target):
    """Check for DNS tunneling indicators."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # Check for TXT records (common tunneling vector)
    try:
        result = subprocess.run(
            ["dig", "+short", clean, "TXT"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        txt_records = [r.strip() for r in result.stdout.splitlines() if r.strip()]

        if txt_records:
            # Check for unusually long TXT records (tunneling indicator)
            for record in txt_records:
                if len(record) > 200:
                    findings.append(
                        {
                            "tipo": "LONG_TXT_RECORD",
                            "tamanho": len(record),
                            "preview": record[:100],
                            "severidade": "MEDIO",
                            "descricao": f"TXT record muito longo ({len(record)} chars) — possível DNS tunneling",
                            "remediacao": "Limitar tamanho de TXT records. Monitorar queries TXT anômalas.",
                        }
                    )

            findings.append(
                {
                    "tipo": "TXT_RECORDS",
                    "quantidade": len(txt_records),
                    "severidade": "INFO",
                    "descricao": f"{len(txt_records)} TXT records encontrados — verificar para tunneling",
                }
            )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # Check for NULL records (tunneling tool indicator)
    try:
        result = subprocess.run(
            ["dig", "+short", clean, "NULL"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.stdout.strip():
            findings.append(
                {
                    "tipo": "NULL_RECORD",
                    "severidade": "ALTO",
                    "descricao": "DNS NULL record encontrado — comum em DNS tunneling (iodine, dnscat2)",
                    "remediacao": "Remover NULL records. Blocar queries NULL no resolver.",
                }
            )
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    # General assessment
    findings.append(
        {
            "tipo": "TUNNELING_ASSESSMENT",
            "severidade": "INFO",
            "descricao": "DNS tunneling viável se TXT/NULL/CNAME não forem monitorados",
            "remeciacao": "Implementar DNS monitoring. Usar DNS firewall. Limitar query types.",
            "ferramentas_teste": ["iodine", "dnscat2", "dns2tcp", "tuns"],
        }
    )

    return findings


def _validate_dnssec(target):
    """Validate DNSSEC configuration."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    try:
        # Check DNSKEY
        result = subprocess.run(
            ["dig", "+short", clean, "DNSKEY"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        dnskeys = [r.strip() for r in result.stdout.splitlines() if r.strip()]

        # Check DS
        ds_result = subprocess.run(
            ["dig", "+short", clean, "DS"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ds_records = [r.strip() for r in ds_result.stdout.splitlines() if r.strip()]

        # Check RRSIG
        rrsig_result = subprocess.run(
            ["dig", "+short", clean, "RRSIG"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        rrsigs = [r.strip() for r in rrsig_result.stdout.splitlines() if r.strip()]

        if not dnskeys and not ds_records:
            findings.append(
                {
                    "tipo": "DNSSEC_NOT_CONFIGURED",
                    "severidade": "ALTO",
                    "descricao": "DNSSEC não configurado — sem proteção contra spoofing de respostas DNS",
                    "remediacao": "Implementar DNSSEC: gerar KSK/ZSK, assinar zona, configurar DS no registrador.",
                }
            )
        elif dnskeys:
            # Parse key info
            for key in dnskeys:
                parts = key.split()
                if len(parts) >= 4:
                    flags = parts[0]
                    algorithm = parts[2]
                    key_type = "KSK" if "257" in flags else "ZSK"

                    # Check algorithm strength
                    weak_algorithms = {"1", "3", "5"}  # RSAMD5, DSA, RSASHA1
                    if algorithm in weak_algorithms:
                        findings.append(
                            {
                                "tipo": "DNSSEC_WEAK_ALGORITHM",
                                "algoritmo": algorithm,
                                "key_type": key_type,
                                "severidade": "ALTO",
                                "descricao": f"DNSSEC usa algoritmo fraco ({algorithm}) para {key_type}",
                                "remediacao": "Migrar para ECDSAP256SHA256 (13) ou ED25519 (15).",
                            }
                        )

            findings.append(
                {
                    "tipo": "DNSSEC_STATUS",
                    "dnskeys": len(dnskeys),
                    "ds_records": len(ds_records),
                    "rrsigs": len(rrsigs),
                    "severidade": "INFO",
                    "descricao": f"DNSSEC configurado: {len(dnskeys)} DNSKEY, {len(ds_records)} DS, {len(rrsigs)} RRSIG",
                }
            )

            # Validate with dig +dnssec
            val_result = subprocess.run(
                ["dig", "+dnssec", "+short", clean, "A"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "flags:.*ad" in val_result.stdout.lower() or "ad" in val_result.stdout.lower():
                findings.append(
                    {
                        "tipo": "DNSSEC_VALIDATION_OK",
                        "severidade": "INFO",
                        "descricao": "DNSSEC validation OK — respostas autenticadas",
                    }
                )

    except FileNotFoundError:
        findings.append(
            {
                "tipo": "DNSSEC_CHECK_SKIP",
                "severidade": "INFO",
                "descricao": "dig não disponível — pular validação DNSSEC",
            }
        )
    except Exception as e:
        findings.append(
            {
                "tipo": "DNSSEC_CHECK_ERROR",
                "severidade": "INFO",
                "descricao": f"Erro ao validar DNSSEC: {str(e)}",
            }
        )

    return findings


def _enumerate_subdomains(target):
    """Enumerate subdomains via wordlist."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    found_subs = []

    for sub in SUBDOMAIN_WORDLIST:
        fqdn = f"{sub}.{clean}"
        try:
            ip = socket.gethostbyname(fqdn)
            found_subs.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            continue
        except Exception as _exc:
            continue

    if found_subs:
        findings.append(
            {
                "tipo": "SUBDOMAINS_FOUND",
                "quantidade": len(found_subs),
                "subdominios": found_subs,
                "severidade": "ALTO",
                "descricao": f"{len(found_subs)} subdomínios descobertos via wordlist",
                "remediacao": "Auditar subdomínios expostos. Implementar wildcard certificates com cuidado.",
            }
        )

        # Check for interesting subdomains
        interesting = [
            s
            for s in found_subs
            if any(
                kw in s["subdomain"]
                for kw in [
                    "admin",
                    "internal",
                    "dev",
                    "staging",
                    "test",
                    "debug",
                    "jenkins",
                    "gitlab",
                    "grafana",
                    "kibana",
                    "elastic",
                ]
            )
        ]
        if interesting:
            findings.append(
                {
                    "tipo": "INTERESTING_SUBDOMAINS",
                    "subdominios": interesting,
                    "severidade": "CRITICO",
                    "descricao": f"{len(interesting)} subdomínios sensíveis encontrados",
                    "remediacao": "Restringir acesso a subdomínios internos. Usar VPN ou IP whitelist.",
                }
            )

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    DNS Recon Deep 2026-Grade — Zone Transfer, Cache Poisoning, Rebinding, Tunneling, DNSSEC.

    Técnicas: zone transfer (AXFR) em todos os NS, cache poisoning assessment
    (DNSSEC/TTL/source port), DNS rebinding (private IP/wildcard), DNS tunneling
    (TXT/NULL records), DNSSEC validation (algorithm strength), subdomain enumeration
    via wordlist (200+ entries).
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "zone_transfer": [],
        "cache_poisoning": [],
        "dns_rebinding": [],
        "dns_tunneling": [],
        "dnssec": [],
        "subdomains": [],
    }

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    resultado["zone_transfer"] = _test_zone_transfer(clean_target)
    resultado["cache_poisoning"] = _test_cache_poisoning(clean_target)
    resultado["dns_rebinding"] = _test_dns_rebinding(clean_target)
    resultado["dns_tunneling"] = _test_dns_tunneling(clean_target)
    resultado["dnssec"] = _validate_dnssec(clean_target)
    resultado["subdomains"] = _enumerate_subdomains(clean_target)

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total > 0 else "LIMPO"),
    }

    return {
        "plugin": "dns_recon_deep",
        "versao": "2026.1",
        "tecnicas": [
            "zone_transfer_axfr",
            "cache_poisoning_check",
            "dns_rebinding",
            "dns_tunneling_detection",
            "dnssec_validation",
            "subdomain_enumeration",
        ],
        "resultados": resultado,
    }
