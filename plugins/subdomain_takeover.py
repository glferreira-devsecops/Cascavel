# plugins/subdomain_takeover.py — Cascavel 2026 Intelligence
import socket
import subprocess

import requests

# Subdomain wordlist for takeover scanning
SUBDOMAIN_WORDLIST = [
    "dev",
    "test",
    "staging",
    "beta",
    "app",
    "api",
    "mail",
    "cdn",
    "status",
    "docs",
    "shop",
    "blog",
    "admin",
    "portal",
    "auth",
    "sso",
    "vpn",
    "git",
    "ci",
    "jenkins",
    "grafana",
    "kibana",
    "demo",
    "sandbox",
    "preview",
    "legacy",
    "old",
    "backup",
    "internal",
    "intranet",
    "extranet",
    "webmail",
    "ftp",
    "smtp",
    "pop",
    "imap",
    "mx",
    "ns",
    "dns",
    "proxy",
    "gateway",
    "lb",
    "load",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "files",
    "upload",
    "download",
    "cdn2",
    "edge",
    "node",
    "worker",
    "job",
    "queue",
    "chat",
    "support",
    "help",
    "wiki",
    "kb",
    "forum",
    "community",
    "social",
    "analytics",
    "stats",
    "metrics",
    "monitor",
    "log",
    "logs",
    "trace",
    "events",
    "webhook",
    "notify",
    "alert",
    "alarm",
]

# Cloud service takeover fingerprints
CLOUD_FINGERPRINTS = {
    "AWS S3": [
        ("NoSuchBucket", "CRITICO"),
        ("The specified bucket does not exist", "CRITICO"),
        ("<Code>NoSuchBucket</Code>", "CRITICO"),
        ("InvalidBucketName", "ALTO"),
        ("AllAccessDisabled", "ALTO"),
        ("AccessDenied", "MEDIO"),
    ],
    "Azure": [
        ("Web App - Pair", "ALTO"),
        ("Error 404 - Web app not found", "CRITICO"),
        ("Azure Web App", "MEDIO"),
        ("This page is under construction", "ALTO"),
    ],
    "Heroku": [
        ("There is no such app", "CRITICO"),
        ("herokucdn.com/error-pages", "CRITICO"),
        ("No such app", "CRITICO"),
    ],
    "GitHub Pages": [
        ("There isn't a GitHub Pages site here", "CRITICO"),
        ("For root URLs (like http://example.com/)", "CRITICO"),
        ("Not Found - Request ID", "ALTO"),
    ],
    "Shopify": [
        ("Sorry, this shop is currently unavailable", "CRITICO"),
        ("Only one step left!", "ALTO"),
        ("This shop is currently unavailable", "CRITICO"),
    ],
    "Zendesk": [
        ("Help Center Closed", "CRITICO"),
        ("this help center no longer exists", "CRITICO"),
    ],
    "Tumblr": [
        ("There's nothing here.", "CRITICO"),
        ("Whatever you were looking for doesn't currently exist", "CRITICO"),
    ],
    "Fastly": [
        ("Fastly error: unknown domain", "CRITICO"),
        ("Fastly", "MEDIO"),
    ],
    "Pantheon": [
        ("404 error unknown site", "CRITICO"),
    ],
    "Surge.sh": [
        ("project not found", "CRITICO"),
    ],
    "Netlify": [
        ("Not Found - Request ID", "ALTO"),
        ("netlify", "MEDIO"),
    ],
    "Ghost": [
        ("The thing you were looking for is no longer here", "CRITICO"),
    ],
    "UserVoice": [
        ("This UserVoice subdomain is currently available", "CRITICO"),
    ],
    "Intercom": [
        ("This page is reserved for", "CRITICO"),
    ],
    "HubSpot": [
        ("Domain is not configured", "ALTO"),
    ],
    "Cargo Collective": [
        ("If you're moving your domain", "ALTO"),
    ],
    "Fly.io": [
        ("404 Not Found", "MEDIO"),
    ],
    "Vercel": [
        ("The deployment could not be found", "CRITICO"),
        ("vercel.app", "MEDIO"),
    ],
    "Render": [
        ("The page you are looking for does not exist", "CRITICO"),
    ],
    "Railway": [
        ("This deployment is not available", "CRITICO"),
    ],
}

# Expired domain TLDs to check
EXPIRED_CHECK_TLDS = [".com", ".net", ".org", ".io", ".co", ".dev", ".app"]


def _check_cname_dangling(subdomain):
    """Check if CNAME record points to a dangling domain."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", subdomain],
            capture_output=True,
            text=True,
            timeout=10,
        )
        cname = result.stdout.strip().rstrip(".")
        if cname:
            try:
                socket.gethostbyname(cname)
                return cname, False  # Resolves — not dangling
            except socket.gaierror:
                return cname, True  # Dangling!
    except FileNotFoundError:
        return None, False
    except Exception:  # noqa: S110
        pass
    return None, False


def _check_cloud_takeover(subdomain, cname=None):
    """Check for cloud service takeover via fingerprints."""
    findings = []
    try:
        resp = requests.get(f"http://{subdomain}", timeout=8, allow_redirects=True, verify=False)
        body = resp.text.lower()
        headers = str(resp.headers).lower()

        for service, fingerprints in CLOUD_FINGERPRINTS.items():
            for fp_text, severity in fingerprints:
                if fp_text.lower() in body or fp_text.lower() in headers:
                    findings.append(
                        {
                            "tipo": "CLOUD_TAKEOVER",
                            "subdominio": subdomain,
                            "servico": service,
                            "indicador": fp_text[:80],
                            "status_http": resp.status_code,
                            "cname": cname or "N/A",
                            "severidade": severity,
                            "descricao": f"Takeover possível via {service} em {subdomain}",
                            "remediacao": f"Reclamar recurso no {service} ou remover CNAME. Implementar monitoramento contínuo.",
                        }
                    )
                    return findings  # First match is enough
    except requests.ConnectionError:
        findings.append(
            {
                "tipo": "CONNECTION_FAILED",
                "subdominio": subdomain,
                "cname": cname or "N/A",
                "severidade": "MEDIO",
                "descricao": f"Subdomínio {subdomain} não resolve — verificar CNAME manualmente",
            }
        )
    except Exception as e:
        findings.append(
            {
                "tipo": "CHECK_ERROR",
                "subdominio": subdomain,
                "severidade": "INFO",
                "descricao": f"Erro ao verificar {subdomain}: {str(e)}",
            }
        )
    return findings


def _check_expired_domains(subdomain):
    """Check if referenced domains are expired."""
    findings = []
    try:
        result = subprocess.run(
            ["dig", "+short", subdomain, "A"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]

        if not ips:
            # Check if domain is registered
            try:
                socket.gethostbyname(subdomain)
            except socket.gaierror:
                findings.append(
                    {
                        "tipo": "DOMAIN_NOT_REGISTERED",
                        "subdominio": subdomain,
                        "severidade": "CRITICO",
                        "descricao": f"Domínio {subdomain} não registrado — takeover trivial",
                        "remediacao": "Registrar o domínio ou remover referências. Monitorar expiração de domínios.",
                    }
                )
    except FileNotFoundError:
        pass
    except Exception:  # noqa: S110
        pass
    return findings


def _check_dns_misconfiguration(subdomain):
    """Check for misconfigured DNS records."""
    findings = []
    try:
        # Check for conflicting records
        a_result = subprocess.run(
            ["dig", "+short", subdomain, "A"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        cname_result = subprocess.run(
            ["dig", "+short", subdomain, "CNAME"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        a_records = [r.strip() for r in a_result.stdout.splitlines() if r.strip()]
        cname = cname_result.stdout.strip()

        if cname and a_records:
            findings.append(
                {
                    "tipo": "CONFLICTING_DNS",
                    "subdominio": subdomain,
                    "a_records": a_records,
                    "cname": cname,
                    "severidade": "ALTO",
                    "descricao": f"CNAME + A records conflitantes em {subdomain} — configuração DNS incorreta",
                    "remediacao": "Remover A records quando CNAME existe, ou vice-versa.",
                }
            )

        # Check for wildcard CNAME pointing to external service
        if cname and not cname.endswith(subdomain):
            external = cname.rstrip(".")
            findings.append(
                {
                    "tipo": "EXTERNAL_CNAME",
                    "subdominio": subdomain,
                    "cname": external,
                    "severidade": "MEDIO",
                    "descricao": f"CNAME aponta para serviço externo: {external} — takeover se serviço for descontinuado",
                    "remediacao": "Monitorar status do serviço externo. Implementar alertas para CNAME dangling.",
                }
            )

    except FileNotFoundError:
        pass
    except Exception:  # noqa: S110
        pass
    return findings


def _check_github_pages_takeover(subdomain, cname=None):
    """Specifically check for GitHub Pages takeover."""
    findings = []
    try:
        resp = requests.get(f"http://{subdomain}", timeout=8, verify=False)
        body = resp.text.lower()

        # GitHub Pages specific indicators
        gh_indicators = [
            "there isn't a github pages site here",
            "for root urls (like http://example.com/)",
            "github pages",
            "githubusercontent",
        ]

        for indicator in gh_indicators:
            if indicator in body:
                findings.append(
                    {
                        "tipo": "GITHUB_PAGES_TAKEOVER",
                        "subdominio": subdomain,
                        "cname": cname or "N/A",
                        "indicador": indicator,
                        "severidade": "CRITICO",
                        "descricao": f"GitHub Pages takeover possível em {subdomain} — CNAME aponta para repo não existente",
                        "remediacao": "Criar repositório GitHub com CNAME file correspondente, ou remover registro DNS.",
                    }
                )
                break
    except Exception:  # noqa: S110
        pass
    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    Subdomain Takeover 2026-Grade — Dangling CNAME, Cloud Services, Expired Domains.

    Técnicas: 50+ subdomain wordlist, CNAME dangling detection,
    cloud service fingerprints (S3/Azure/Heroku/GitHub Pages/Shopify/Zendesk/
    Tumblr/Fastly/Pantheon/Surge/Netlify/Ghost/UserVoice/Intercom/HubSpot/
    Vercel/Render/Railway), expired domain detection, DNS misconfiguration
    check, GitHub Pages specific takeover test.
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "dangling_cname": [],
        "cloud_takeover": [],
        "expired_domains": [],
        "dns_misconfiguration": [],
        "github_pages": [],
    }

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    tested_subs = set()
    for prefix in SUBDOMAIN_WORDLIST:
        subdomain = f"{prefix}.{clean_target}"
        if subdomain in tested_subs:
            continue
        tested_subs.add(subdomain)

        # CNAME dangling check
        cname, is_dangling = _check_cname_dangling(subdomain)
        if is_dangling:
            resultado["dangling_cname"].append(
                {
                    "subdominio": subdomain,
                    "cname": cname,
                    "severidade": "CRITICO",
                    "descricao": f"CNAME {cname} não resolve — subdomain takeover confirmado!",
                    "remediacao": "Remover CNAME ou reclamar recurso no serviço de destino.",
                }
            )
            # If dangling, check for specific takeover
            resultado["cloud_takeover"].extend(_check_cloud_takeover(subdomain, cname))
            resultado["github_pages"].extend(_check_github_pages_takeover(subdomain, cname))
            continue

        # Even if not dangling, check for cloud takeover fingerprints
        resultado["cloud_takeover"].extend(_check_cloud_takeover(subdomain, cname))

        # Check expired domains
        resultado["expired_domains"].extend(_check_expired_domains(subdomain))

        # Check DNS misconfiguration
        resultado["dns_misconfiguration"].extend(_check_dns_misconfiguration(subdomain))

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
        "subdominios_testados": len(tested_subs),
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total > 0 else "LIMPO"),
    }

    return {
        "plugin": "subdomain_takeover",
        "versao": "2026.1",
        "tecnicas": [
            "cname_dangling",
            "cloud_fingerprints_20plus",
            "expired_domain_check",
            "dns_misconfiguration",
            "github_pages_takeover",
        ],
        "resultados": resultado,
    }
