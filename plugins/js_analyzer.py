# plugins/js_analyzer.py
import re

import requests

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET": r'(?:aws_secret|secret_key)["\s:=]+[A-Za-z0-9/+=]{40}',
    "GITHUB_TOKEN": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "GITHUB_FINE_GRAINED": r"github_pat_[A-Za-z0-9_]{82}",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "STRIPE_SECRET": r"sk_live_[A-Za-z0-9]{24,}",
    "STRIPE_PUBLISHABLE": r"pk_live_[A-Za-z0-9]{24,}",
    "SLACK_TOKEN": r"xox[bpors]-[0-9]{10,}-[A-Za-z0-9]{10,}",
    "SLACK_WEBHOOK": r"hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    "FIREBASE_API": r"AIza[0-9A-Za-z\-_]{35}",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "JWT_SECRET": r'(?:jwt_secret|JWT_SECRET|jwt\.secret)["\s:=]+[A-Za-z0-9]{8,}',
    "HEROKU_API": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "TWILIO_SID": r"AC[a-f0-9]{32}",
    "SENDGRID_KEY": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "DISCORD_TOKEN": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
    "OPENAI_KEY": r"sk-[A-Za-z0-9]{48}",
    "SUPABASE_KEY": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
}

ENDPOINT_PATTERNS = [
    r'(?:fetch|axios|XMLHttpRequest|\.ajax)\s*\(\s*["\']([^"\']+)',
    r'(?:api_url|apiUrl|API_URL|baseURL|endpoint)\s*[:=]\s*["\']([^"\']+)',
    r'https?://[a-zA-Z0-9\-\.]+/api/[^\s"\'<>]+',
]


def _collect_js_urls(target):
    """Busca e normaliza URLs de arquivos JavaScript da página principal."""
    resp = requests.get(f"http://{target}/", timeout=8)
    raw = re.findall(r'(?:src|href)=["\']([ ^"\']*\.js[^"\']*)', resp.text)
    unique = list(set(raw))[:20]
    normalized = []
    for url in unique:
        if url.startswith("//"):
            url = f"http:{url}"
        elif url.startswith("/"):
            url = f"http://{target}{url}"
        elif not url.startswith("http"):
            url = f"http://{target}/{url}"
        normalized.append(url)
    return normalized


def _scan_secrets(content, filename):
    """Busca padrões de segredos em conteúdo JS."""
    findings = []
    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches[:3]:
            sev = "CRITICO" if ("SECRET" in secret_name or "PRIVATE" in secret_name) else "ALTO"
            findings.append(
                {
                    "tipo": secret_name,
                    "arquivo": filename,
                    "valor_parcial": str(match)[:15] + "...",
                    "severidade": sev,
                }
            )
    return findings


def _scan_endpoints(content, filename):
    """Busca endpoints de API em conteúdo JS."""
    found = []
    for pattern in ENDPOINT_PATTERNS:
        endpoints = re.findall(pattern, content)
        for ep in endpoints[:5]:
            if ep.startswith("http") or ep.startswith("/api"):
                found.append({"endpoint": ep[:100], "arquivo": filename})
    return found


def _check_supply_chain(content, js_url, filename):
    """Verifica source maps expostos e ausência de SRI."""
    vulns = []
    if "//# sourceMappingURL=" in content:
        map_url = re.search(r"sourceMappingURL=(\S+)", content)
        if map_url:
            vulns.append(
                {
                    "tipo": "SOURCE_MAP_EXPOSED",
                    "arquivo": filename,
                    "map_url": map_url.group(1),
                    "severidade": "MEDIO",
                    "descricao": "Source map exposto — código fonte original acessível!",
                }
            )
    if "integrity=" not in content and "cdn" in js_url.lower():
        vulns.append(
            {
                "tipo": "SEM_SRI",
                "arquivo": filename,
                "severidade": "MEDIO",
                "descricao": "CDN JS sem Subresource Integrity — supply chain attack risk!",
            }
        )
    return vulns


def run(target, ip, open_ports, banners):
    """
    Análise de JavaScript para segredos, endpoints, e supply chain risks.
    2026 Intel: OWASP A03 (Supply Chain Failures), client-side supply chain,
    SRI checks, inline secrets, API key patterns, source maps.
    """
    _ = (ip, open_ports, banners)  # Standardized plugin signature
    resultado = {"segredos": [], "endpoints": [], "vulns": []}

    try:
        js_files = _collect_js_urls(target)
    except Exception:
        return {"plugin": "js_analyzer", "resultados": "Erro ao buscar página principal"}

    for js_url in js_files:
        try:
            resp = requests.get(js_url, timeout=8)
            content = resp.text
            filename = js_url.split("/")[-1]

            resultado["segredos"].extend(_scan_secrets(content, filename))
            resultado["endpoints"].extend(_scan_endpoints(content, filename))
            resultado["vulns"].extend(_check_supply_chain(content, js_url, filename))
        except Exception:
            continue

    resultado["endpoints"] = resultado["endpoints"][:20]
    return {"plugin": "js_analyzer", "resultados": resultado}
