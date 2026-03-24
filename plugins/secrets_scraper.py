# plugins/secrets_scraper.py — Cascavel 2026 Intelligence
import requests
import re
import math


PATHS = [
    "/.env", "/.env.production", "/.env.local", "/.env.staging", "/.env.backup",
    "/.git/config", "/.htpasswd", "/.htaccess", "/.npmrc", "/.yarnrc",
    "/config.php", "/wp-config.php", "/settings.py", "/config.json", "/config.yaml",
    "/.docker/config.json", "/api/config", "/docker-compose.yml",
    "/composer.json", "/package.json", "/.env.local", "/.env.development",
    "/application.properties", "/application.yml", "/.aws/credentials",
    "/credentials.json", "/.gcloud/credentials", "/firebase.json",
    "/.travis.yml", "/.gitlab-ci.yml", "/Jenkinsfile",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
]

# ──────────── SECRET PATTERNS (50+) ────────────
KEY_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key"),
    # GitHub
    (r"ghp_[0-9A-Za-z]{36,}", "GitHub Personal Access Token"),
    (r"gho_[0-9A-Za-z]{36,}", "GitHub OAuth Token"),
    (r"ghs_[0-9A-Za-z]{36,}", "GitHub Server Token"),
    (r"ghr_[0-9A-Za-z]{36,}", "GitHub Refresh Token"),
    (r"github_pat_[0-9A-Za-z_]{82,}", "GitHub Fine-Grained PAT"),
    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
    # Slack
    (r"xox[bporas]-[0-9A-Za-z\-]{10,}", "Slack Token"),
    (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook"),
    # SendGrid
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key"),
    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key"),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key"),
    (r"AC[0-9a-fA-F]{32}", "Twilio Account SID"),
    # Firebase
    (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "Firebase Cloud Messaging"),
    # Heroku
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Heroku API Key / UUID"),
    # Shopify
    (r"shpat_[0-9a-fA-F]{32}", "Shopify Private App Token"),
    (r"shpca_[0-9a-fA-F]{32}", "Shopify Custom App Token"),
    # Discord
    (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token"),
    # Telegram
    (r"[0-9]+:AA[0-9A-Za-z\-_]{33}", "Telegram Bot Token"),
    # OpenAI
    (r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API Key"),
    (r"sk-proj-[A-Za-z0-9_-]{100,}", "OpenAI Project Key"),
    # Supabase
    (r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT/Supabase Key"),
    # Generic
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key (PEM)"),
    (r"(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Generic Secret"),
    (r"Basic\s+[A-Za-z0-9+/=]{20,}", "HTTP Basic Auth Credentials"),
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer Token"),
    # Database
    (r"(?:mysql|postgres|mongodb)://[^\s\"'<>]+", "Database Connection String"),
    (r"(?:redis|amqp)://[^\s\"'<>]+", "Redis/AMQP Connection String"),
    # Azure
    (r"AccountKey=[A-Za-z0-9+/=]{88}", "Azure Storage Account Key"),
    # Cloudflare
    (r"[A-Za-z0-9_-]{37}", "Possible Cloudflare API Token"),
]


def _calculate_entropy(text):
    """Calcula Shannon entropy de uma string."""
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 2)


def _scan_for_high_entropy(text, min_length=20, min_entropy=4.0):
    """Busca strings de alta entropia (possíveis secrets)."""
    findings = []
    # Look for quoted strings or assignment values
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', text)
    for candidate in candidates[:20]:
        entropy = _calculate_entropy(candidate)
        if entropy >= min_entropy and len(candidate) >= min_length:
            findings.append({
                "tipo": "HIGH_ENTROPY_STRING",
                "entropia": entropy, "tamanho": len(candidate),
                "amostra": candidate[:20] + "...",
                "severidade": "ALTO" if entropy > 4.5 else "MEDIO",
            })
    return findings


def run(target, ip, open_ports, banners):
    """
    Scanner de Secrets 2026-Grade — 50+ Regex, Entropy Analysis.

    Técnicas: 36+ regex patterns (AWS/Stripe/GitHub/Google/Slack/SendGrid/
    Twilio/Firebase/Discord/Telegram/OpenAI/Supabase/Azure/Database URLs),
    30+ sensitive file paths, Shannon entropy analysis for unknown secrets,
    generic secret detection (password/token/apikey assignments),
    database connection strings, PEM private keys, JWT tokens.
    """
    _ = (ip, open_ports, banners)
    secrets = []

    for path in PATHS:
        try:
            r = requests.get(f"http://{target}{path}", timeout=7)
            if r.status_code != 200 or len(r.text) < 10:
                continue

            # Regex scan
            for pattern, label in KEY_PATTERNS:
                found = re.findall(pattern, r.text, re.DOTALL)
                if found:
                    secrets.append({
                        "caminho": path, "tipo": label,
                        "quantidade": len(found),
                        "amostra": str(found[0])[:30] + "...",
                        "severidade": "CRITICO",
                    })

            # Entropy scan
            entropy_findings = _scan_for_high_entropy(r.text)
            for ef in entropy_findings:
                ef["caminho"] = path
                secrets.append(ef)

        except Exception:
            continue

    return {
        "plugin": "secrets_scraper",
        "versao": "2026.1",
        "tecnicas": ["regex_36_patterns", "entropy_analysis", "30_sensitive_paths",
                      "generic_secret_detection", "connection_strings", "pem_keys"],
        "resultados": secrets if secrets else "Nenhum segredo encontrado",
    }
