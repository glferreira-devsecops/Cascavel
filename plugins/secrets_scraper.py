# plugins/secrets_scraper.py
def run(target, ip, open_ports, banners):
    """
    Procura segredos e credenciais expostos em arquivos sensíveis do alvo.
    Detecta AWS keys, Stripe keys, GitHub tokens, Google API keys, SendGrid, PEM keys.
    """
    import requests
    import re

    paths = [
        "/.env", "/.git/config", "/.htpasswd", "/.htaccess",
        "/config.php", "/wp-config.php", "/settings.py", "/config.json",
        "/.docker/config.json", "/api/config", "/.npmrc",
        "/composer.json", "/package.json", "/.env.local", "/.env.production",
    ]
    secrets = []
    key_patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key"),
        (r"ghp_[0-9A-Za-z]{36,}", "GitHub Personal Token"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid Key"),
        (r"xox[bporas]-[0-9A-Za-z\-]{10,}", "Slack Token"),
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private Key (PEM)"),
    ]

    for path in paths:
        try:
            r = requests.get(f"http://{target}{path}", timeout=7)
            if r.status_code != 200:
                continue
            for pattern, label in key_patterns:
                encontrados = re.findall(pattern, r.text, re.DOTALL)
                if encontrados:
                    secrets.append({
                        "caminho": path,
                        "tipo": label,
                        "quantidade": len(encontrados),
                        "amostra": encontrados[0][:30] + "..."
                    })
        except Exception:
            continue

    return {
        "plugin": "secrets_scraper",
        "resultados": secrets if secrets else "Nenhum segredo encontrado"
    }
