# plugins/secrets_scraper.py
def run(target, results):
    """
    Procura segredos e credenciais expostos em arquivos sensíveis do alvo.
    Integra-se ao core e retorna em formato JSON, pronto para análise.
    """
    import requests, re
    paths = [
        "/.env",
        "/.git/config",
        "/.htpasswd",
        "/.htaccess",
        "/config.php",
        "/wp-config.php",
        "/settings.py",
        "/config.json"
    ]
    secrets = []
    key_patterns = [
        r"AKIA[0-9A-Z]{16}",                 # AWS key
        r"sk_live_[0-9a-zA-Z]{24,}",         # Stripe
        r"ghp_[0-9A-Za-z]{36,}",             # GitHub token
        r"AIza[0-9A-Za-z\-_]{35}",           # Google API Key
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",  # SendGrid Key
        r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", # Private Key (PEM)
    ]
    for path in paths:
        try:
            r = requests.get(f"http://{target}{path}", timeout=7)
            for pattern in key_patterns:
                encontrados = re.findall(pattern, r.text, re.DOTALL)
                if encontrados:
                    secrets.append({"caminho": path, "segredos": encontrados})
        except Exception:
            continue
    results["secrets_scraper"] = secrets if secrets else "Nenhum segredo encontrado"
