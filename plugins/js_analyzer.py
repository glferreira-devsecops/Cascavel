# plugins/js_analyzer.py
def run(target, ip, open_ports, banners):
    """
    Análise de JavaScript para segredos, endpoints, e supply chain risks.
    2026 Intel: OWASP A03 (Supply Chain Failures), client-side supply chain,
    SRI checks, inline secrets, API key patterns, source maps.
    """
    import requests
    import re

    resultado = {"segredos": [], "endpoints": [], "vulns": []}

    # Buscar JS files
    try:
        resp = requests.get(f"http://{target}/", timeout=8)
        js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)', resp.text)
        js_files = list(set(js_files))[:20]
    except Exception:
        return {"plugin": "js_analyzer", "resultados": "Erro ao buscar página principal"}

    # Padrões de segredos (2026 expanded)
    secret_patterns = {
        "AWS_ACCESS_KEY": r'AKIA[0-9A-Z]{16}',
        "AWS_SECRET": r'(?:aws_secret|secret_key)["\s:=]+[A-Za-z0-9/+=]{40}',
        "GITHUB_TOKEN": r'gh[ps]_[A-Za-z0-9_]{36,}',
        "GITHUB_FINE_GRAINED": r'github_pat_[A-Za-z0-9_]{82}',
        "GOOGLE_API_KEY": r'AIza[0-9A-Za-z\-_]{35}',
        "STRIPE_SECRET": r'sk_live_[A-Za-z0-9]{24,}',
        "STRIPE_PUBLISHABLE": r'pk_live_[A-Za-z0-9]{24,}',
        "SLACK_TOKEN": r'xox[bpors]-[0-9]{10,}-[A-Za-z0-9]{10,}',
        "SLACK_WEBHOOK": r'hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
        "FIREBASE_API": r'AIza[0-9A-Za-z\-_]{35}',
        "PRIVATE_KEY": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "JWT_SECRET": r'(?:jwt_secret|JWT_SECRET|jwt\.secret)["\s:=]+[A-Za-z0-9]{8,}',
        "HEROKU_API": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        "TWILIO_SID": r'AC[a-f0-9]{32}',
        "SENDGRID_KEY": r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
        "DISCORD_TOKEN": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}',
        "OPENAI_KEY": r'sk-[A-Za-z0-9]{48}',
        "SUPABASE_KEY": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    }

    # API endpoint patterns
    endpoint_patterns = [
        r'(?:fetch|axios|XMLHttpRequest|\.ajax)\s*\(\s*["\']([^"\']+)',
        r'(?:api_url|apiUrl|API_URL|baseURL|endpoint)\s*[:=]\s*["\']([^"\']+)',
        r'https?://[a-zA-Z0-9\-\.]+/api/[^\s"\'<>]+',
    ]

    for js_url in js_files:
        if js_url.startswith("//"):
            js_url = f"http:{js_url}"
        elif js_url.startswith("/"):
            js_url = f"http://{target}{js_url}"
        elif not js_url.startswith("http"):
            js_url = f"http://{target}/{js_url}"

        try:
            resp = requests.get(js_url, timeout=8)
            content = resp.text

            # Buscar segredos
            for secret_name, pattern in secret_patterns.items():
                matches = re.findall(pattern, content)
                for match in matches[:3]:
                    resultado["segredos"].append({
                        "tipo": secret_name, "arquivo": js_url.split("/")[-1],
                        "valor_parcial": match[:15] + "...",
                        "severidade": "CRITICO" if "SECRET" in secret_name or "PRIVATE" in secret_name else "ALTO",
                    })

            # Buscar endpoints
            for pattern in endpoint_patterns:
                endpoints = re.findall(pattern, content)
                for ep in endpoints[:5]:
                    if ep.startswith("http") or ep.startswith("/api"):
                        resultado["endpoints"].append({"endpoint": ep[:100], "arquivo": js_url.split("/")[-1]})

            # Source map check
            if "//# sourceMappingURL=" in content:
                map_url = re.search(r'sourceMappingURL=(\S+)', content)
                if map_url:
                    resultado["vulns"].append({
                        "tipo": "SOURCE_MAP_EXPOSED", "arquivo": js_url.split("/")[-1],
                        "map_url": map_url.group(1), "severidade": "MEDIO",
                        "descricao": "Source map exposto — código fonte original acessível!"
                    })

            # SRI check (Supply Chain 2026)
            if "integrity=" not in resp.text and "cdn" in js_url.lower():
                resultado["vulns"].append({
                    "tipo": "SEM_SRI", "arquivo": js_url.split("/")[-1],
                    "severidade": "MEDIO",
                    "descricao": "CDN JS sem Subresource Integrity — supply chain attack risk!"
                })

        except Exception:
            continue

    resultado["endpoints"] = resultado["endpoints"][:20]
    return {"plugin": "js_analyzer", "resultados": resultado}
