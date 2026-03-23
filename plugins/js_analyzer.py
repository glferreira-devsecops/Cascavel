# plugins/js_analyzer.py
def run(target, ip, open_ports, banners):
    """
    Analisa arquivos JavaScript do alvo para extrair segredos, endpoints e API keys.
    Faz crawl da página principal, identifica JS, baixa e analisa cada um.
    """
    import requests
    import re

    resultado = {"js_files": [], "segredos": [], "endpoints": [], "total_js": 0}

    # 1. Buscar JS files da página principal
    js_urls = set()
    try:
        resp = requests.get(f"http://{target}", timeout=8)
        # Extrair src de tags script
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        for src in scripts:
            if src.startswith("//"):
                src = "http:" + src
            elif src.startswith("/"):
                src = f"http://{target}{src}"
            elif not src.startswith("http"):
                src = f"http://{target}/{src}"
            js_urls.add(src)
    except Exception as e:
        resultado["erro_crawl"] = str(e)

    # Adicionar JS comuns que podem existir
    js_comuns = [
        f"http://{target}/app.js", f"http://{target}/main.js",
        f"http://{target}/bundle.js", f"http://{target}/config.js",
        f"http://{target}/env.js", f"http://{target}/settings.js",
    ]
    js_urls.update(js_comuns)

    resultado["total_js"] = len(js_urls)

    # Padrões de segredos em JS
    secret_patterns = [
        (r"(?:api[_-]?key|apikey)['\"\s]*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API_KEY"),
        (r"(?:secret|token|password|passwd|pwd)['\"\s]*[:=]\s*['\"]([^\s'\"]{8,})['\"]", "SECRET/TOKEN"),
        (r"AKIA[0-9A-Z]{16}", "AWS_KEY"),
        (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "GITHUB_TOKEN"),
        (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_API_KEY"),
        (r"sk[-_](?:live|test)[-_][0-9a-zA-Z]{24,}", "STRIPE_KEY"),
        (r"xox[bporas]-[0-9A-Za-z\-]{10,}", "SLACK_TOKEN"),
        (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "JWT_TOKEN"),
        (r"(?:firebase|supabase)['\"\s]*[:=]\s*['\"]([^\s'\"]{20,})['\"]", "FIREBASE/SUPABASE"),
    ]

    # Padrões de endpoints
    endpoint_patterns = [
        r'(?:fetch|axios|XMLHttpRequest|ajax)\s*\(\s*[\'"]([^\'"]+)[\'"]',
        r'(?:url|endpoint|href|api)[\'"\s]*[:=]\s*[\'"](/[^\'"]+)[\'"]',
        r'https?://[^\s\'"<>]+/api/[^\s\'"<>]+',
    ]

    # 2. Analisar cada JS
    for js_url in list(js_urls)[:15]:  # Limitar a 15 JS files
        try:
            js_resp = requests.get(js_url, timeout=8)
            if js_resp.status_code != 200 or len(js_resp.text) < 50:
                continue

            resultado["js_files"].append(js_url)

            # Buscar segredos
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, js_resp.text)
                for match in matches[:3]:
                    resultado["segredos"].append({
                        "arquivo": js_url.split("/")[-1],
                        "tipo": label,
                        "amostra": match[:40] + "..." if len(match) > 40 else match,
                    })

            # Buscar endpoints
            for pattern in endpoint_patterns:
                matches = re.findall(pattern, js_resp.text)
                for match in matches[:10]:
                    if len(match) > 5 and match not in resultado["endpoints"]:
                        resultado["endpoints"].append(match)

        except Exception:
            continue

    resultado["endpoints"] = resultado["endpoints"][:30]
    resultado["segredos"] = resultado["segredos"][:20]

    return {"plugin": "js_analyzer", "resultados": resultado}
