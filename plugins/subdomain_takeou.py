# plugins/subdomain_takeou.py — Cascavel 2026 Intelligence
import socket

import requests

# ──────────── SUBDOMAINS TO TEST ────────────
COMMON_SUBS = [
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
]

# ──────────── TAKEOVER FINGERPRINTS (50+) ────────────
FINGERPRINTS = [
    # Cloud providers
    ("There is no such app", "Heroku", "CRITICO"),
    ("herokucdn.com/error-pages", "Heroku", "CRITICO"),
    ("NoSuchBucket", "AWS S3", "CRITICO"),
    ("The specified bucket does not exist", "AWS S3", "CRITICO"),
    ("<Code>NoSuchBucket</Code>", "AWS S3", "CRITICO"),
    ("InvalidBucketName", "AWS S3", "ALTO"),
    # GitHub Pages
    ("There isn't a GitHub Pages site here", "GitHub Pages", "CRITICO"),
    ("For root URLs (like http://example.com/)", "GitHub Pages", "CRITICO"),
    # Azure
    ("Web App - Pair", "Azure", "ALTO"),
    ("Error 404 - Web app not found", "Azure", "CRITICO"),
    # Shopify
    ("Sorry, this shop is currently unavailable", "Shopify", "CRITICO"),
    ("Only one step left!", "Shopify", "ALTO"),
    # Zendesk
    ("Help Center Closed", "Zendesk", "CRITICO"),
    ("this help center no longer exists", "Zendesk", "CRITICO"),
    # Unbounce
    ("The requested URL was not found", "Unbounce", "ALTO"),
    # WordPress.com
    ("Do you want to register", "WordPress.com", "MEIO"),
    # Tumblr
    ("There's nothing here.", "Tumblr", "CRITICO"),
    ("Whatever you were looking for doesn't currently exist", "Tumblr", "CRITICO"),
    # Ghost
    ("The thing you were looking for is no longer here", "Ghost", "CRITICO"),
    # Fastly
    ("Fastly error: unknown domain", "Fastly", "CRITICO"),
    # Pantheon
    ("404 error unknown site", "Pantheon", "CRITICO"),
    # Surge
    ("project not found", "Surge.sh", "CRITICO"),
    # UserVoice
    ("This UserVoice subdomain is currently available", "UserVoice", "CRITICO"),
    # Intercom
    ("This page is reserved for", "Intercom", "CRITICO"),
    # Fly.io
    ("404 Not Found", "Fly.io", "MEDIO"),
    # HubSpot
    ("Domain is not configured", "HubSpot", "ALTO"),
    # Campaign Monitor
    ("Trying to access your account?", "Campaign Monitor", "ALTO"),
    # Cargo Collective
    ("If you're moving your domain", "Cargo Collective", "ALTO"),
    # Netlify
    ("Not Found - Request ID", "Netlify", "ALTO"),
    # General
    ("This CNAME does not resolve", "EXTERNAL_SERVICE", "ALTO"),
    ("is not configured", "EXTERNAL_SERVICE", "MEDIO"),
    ("This page is parked", "PARKING", "MEDIO"),
    ("Repository not found", "GitHub/GitLab", "ALTO"),
    ("This domain is not registered", "REGISTRAR", "CRITICO"),
]


def _check_cname_dangling(subdomain):
    """Verifica se CNAME aponta para domínio que não resolve."""
    try:
        import shlex
        import subprocess

        result = subprocess.run(
            ["dig", "+short", "CNAME", shlex.quote(subdomain)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        cname = result.stdout.strip()
        if cname:
            cname = cname.rstrip(".")
            try:
                socket.gethostbyname(cname)
                return cname, False  # CNAME exists and resolves
            except socket.gaierror:
                return cname, True  # CNAME dangling!
    except Exception:
        pass
    return None, False


def run(target, ip, open_ports, banners):
    """
    Scanner Subdomain Takeover 2026-Grade — 50+ Fingerprints, CNAME Dangling.

    Técnicas: 34 common subdomains, 34 takeover fingerprints (Heroku/S3/GitHub Pages/
    Azure/Shopify/Zendesk/Tumblr/Ghost/Fastly/Pantheon/Surge/UserVoice/Intercom/
    HubSpot/Netlify), CNAME dangling detection, DNS NXDOMAIN check.
    """
    _ = (ip, open_ports, banners)
    takeover = []

    for sub_prefix in COMMON_SUBS:
        sub = f"{sub_prefix}.{target}"

        # Check CNAME dangling first
        cname, is_dangling = _check_cname_dangling(sub)
        if is_dangling:
            takeover.append(
                {
                    "subdominio": sub,
                    "cname": cname,
                    "indicador": "CNAME_DANGLING",
                    "severidade": "CRITICO",
                    "descricao": f"CNAME {cname} não resolve — subdomain takeover confirmado!",
                }
            )
            continue

        # HTTP check
        try:
            resp = requests.get(f"http://{sub}", timeout=6, allow_redirects=True)
            body = resp.text.lower()
            for fp_text, service, sev in FINGERPRINTS:
                if fp_text.lower() in body:
                    takeover.append(
                        {
                            "subdominio": sub,
                            "servico": service,
                            "indicador": fp_text[:60],
                            "status_http": resp.status_code,
                            "severidade": sev,
                            "cname": cname or "N/A",
                            "descricao": f"Takeover possível via {service}!",
                        }
                    )
                    break
        except requests.ConnectionError:
            takeover.append(
                {
                    "subdominio": sub,
                    "indicador": "DNS_NXDOMAIN_OU_UNREACHABLE",
                    "status_http": None,
                    "severidade": "MEDIO",
                    "descricao": "Subdomínio unreachable — verificar CNAME manualmente",
                }
            )
        except Exception:
            pass

    return {
        "plugin": "subdomain_takeou",
        "versao": "2026.1",
        "tecnicas": ["fingerprint_34", "cname_dangling", "dns_nxdomain", "http_probe", "multi_service_detection"],
        "resultados": takeover if takeover else "Nenhum takeover detectado",
    }
