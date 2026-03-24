# plugins/tech_fingerprint.py — Cascavel 2026 Intelligence
import re

import requests

# ──────────── TECHNOLOGY SIGNATURES (2026 Expanded) ────────────
TECH_SIGNATURES = {
    "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net", "X-AspNet-Version"],
    "PHP": ["PHPSESSID", "X-Powered-By: PHP", "php/"],
    "Django": ["csrfmiddlewaretoken", "django", "__admin__"],
    "Rails": ["_rails_session", "X-Runtime", "action_dispatch"],
    "Spring": ["JSESSIONID", "X-Application-Context", "whitelabel"],
    "Express": ["connect.sid", "X-Powered-By: Express"],
    "Next.js": ["__next", "_next/static", "__NEXT_DATA__"],
    "Nuxt.js": ["__nuxt", "_nuxt/", "nuxt"],
    "Laravel": ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Flask": ["session=", "Werkzeug"],
    "FastAPI": ["fastapi", "openapi.json"],
    "WordPress": ["wp-content", "wp-json", "wp-includes"],
    "Drupal": ["drupal", "X-Drupal-Cache", "sites/default"],
    "Joomla": ["joomla", "/administrator/", "com_content"],
    "React": ["_reactRoot", "data-reactroot", "react-app"],
    "Angular": ["ng-app", "ng-controller", "angular", "ng-version"],
    "Vue.js": ["data-v-", "__vue__", "vue-router"],
    "Svelte": ["svelte", "__svelte"],
    "Gatsby": ["gatsby", "__gatsby"],
    "Strapi": ["strapi", "/admin/"],
    "Nginx": ["nginx"],
    "Apache": ["Apache/", "apache"],
    "IIS": ["Microsoft-IIS", "ASP.NET"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS": ["AmazonS3", "x-amz-", "aws"],
    "Vercel": ["x-vercel", "vercel"],
    "Netlify": ["netlify", "x-nf-"],
    "Heroku": ["heroku", "herokuapp"],
    "GraphQL": ["graphql", "__schema", "query {"],
    "Docker": ["docker", "container"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Elasticsearch": ["elasticsearch", "_cluster"],
    "Redis": ["redis"],
    "MongoDB": ["mongodb", "mongo"],
}

# ──────────── SECURITY HEADERS (2026 Complete) ────────────
SEC_HEADERS = {
    "Strict-Transport-Security": ("HSTS", "ALTO"),
    "Content-Security-Policy": ("CSP", "ALTO"),
    "X-Content-Type-Options": ("XCTO", "MEDIO"),
    "X-Frame-Options": ("XFO", "MEDIO"),
    "X-XSS-Protection": ("X-XSS", "INFO"),
    "Referrer-Policy": ("REFERRER", "MEDIO"),
    "Permissions-Policy": ("PERMISSIONS", "MEDIO"),
    "Cross-Origin-Embedder-Policy": ("COEP", "BAIXO"),
    "Cross-Origin-Opener-Policy": ("COOP", "BAIXO"),
    "Cross-Origin-Resource-Policy": ("CORP", "BAIXO"),
    "Cache-Control": ("CACHE", "BAIXO"),
}

# ──────────── JS FRAMEWORK DETECTION ────────────
JS_PATTERNS = [
    (r'<script[^>]*src="[^"]*react[^"]*"', "React"),
    (r'<script[^>]*src="[^"]*angular[^"]*"', "Angular"),
    (r'<script[^>]*src="[^"]*vue[^"]*"', "Vue.js"),
    (r'<script[^>]*src="[^"]*jquery[^"]*"', "jQuery"),
    (r'<script[^>]*src="[^"]*bootstrap[^"]*"', "Bootstrap"),
    (r'<script[^>]*src="[^"]*tailwind[^"]*"', "Tailwind CSS"),
    (r'<link[^>]*href="[^"]*google[^"]*fonts', "Google Fonts"),
]


def _detect_tech(resp, headers):
    """Detecta tecnologias a partir da resposta HTTP."""
    techs = {}
    vulns = []

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    via = headers.get("Via", "")

    if server:
        techs["server"] = server
        # Check for version disclosure
        if re.search(r"[\d.]+", server):
            vulns.append(
                {
                    "tipo": "SERVER_VERSION_DISCLOSED",
                    "header": "Server",
                    "valor": server[:80],
                    "severidade": "BAIXO",
                    "descricao": f"Server version exposed: {server[:80]}",
                }
            )
    if powered:
        techs["x_powered_by"] = powered
        vulns.append(
            {
                "tipo": "X_POWERED_BY_EXPOSED",
                "header": "X-Powered-By",
                "valor": powered,
                "severidade": "BAIXO",
                "descricao": "X-Powered-By expõe stack — remover em produção",
            }
        )
    if via:
        techs["via"] = via

    combined = resp.text.lower() + str(headers).lower()
    for tech, indicators in TECH_SIGNATURES.items():
        for ind in indicators:
            if ind.lower() in combined:
                techs[tech] = True
                break

    # JS pattern matching
    for pattern, tech_name in JS_PATTERNS:
        if re.search(pattern, resp.text, re.IGNORECASE):
            techs[tech_name] = True

    return techs, vulns


def _audit_security_headers(headers):
    """Audita security headers contra best practices 2026."""
    found = {}
    ausentes = []
    vulns = []

    for header, (label, sev) in SEC_HEADERS.items():
        val = headers.get(header, "")
        if val:
            found[label] = val[:100]

            # HSTS analysis
            if label == "HSTS":
                if "includeSubDomains" not in val:
                    vulns.append(
                        {
                            "tipo": "HSTS_NO_SUBDOMAINS",
                            "severidade": "MEDIO",
                            "descricao": "HSTS sem includeSubDomains!",
                        }
                    )
                max_age_match = re.search(r"max-age=(\d+)", val)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    vulns.append(
                        {
                            "tipo": "HSTS_SHORT_MAX_AGE",
                            "severidade": "MEDIO",
                            "max_age": max_age_match.group(1),
                            "descricao": "HSTS max-age < 1 ano!",
                        }
                    )
                if "preload" not in val:
                    vulns.append(
                        {
                            "tipo": "HSTS_NO_PRELOAD",
                            "severidade": "BAIXO",
                            "descricao": "HSTS sem preload — não está na lista HSTS preload!",
                        }
                    )

            # X-XSS-Protection deprecated
            if label == "X-XSS":
                if val.strip() == "1; mode=block":
                    vulns.append(
                        {
                            "tipo": "X_XSS_DEPRECATED",
                            "severidade": "INFO",
                            "descricao": "X-XSS-Protection deprecated — substituir por CSP!",
                        }
                    )
        else:
            ausentes.append(label)
            if sev in ("ALTO", "MEDIO"):
                vulns.append(
                    {
                        "tipo": "HEADER_AUSENTE",
                        "header": header,
                        "label": label,
                        "severidade": sev,
                    }
                )

    found["ausentes"] = ausentes
    return found, vulns


def _audit_cookies(headers):
    """Audita flags de segurança nos cookies."""
    vulns = []
    cookies = headers.get("Set-Cookie", "")
    if not cookies:
        return vulns

    lower = cookies.lower()
    cookie_name = cookies.split("=")[0] if "=" in cookies else "unknown"

    if "httponly" not in lower:
        vulns.append(
            {
                "tipo": "COOKIE_SEM_HTTPONLY",
                "cookie": cookie_name[:30],
                "severidade": "ALTO",
                "descricao": "Cookie sem HttpOnly — acessível via JavaScript (XSS)!",
            }
        )
    if "secure" not in lower:
        vulns.append(
            {
                "tipo": "COOKIE_SEM_SECURE",
                "cookie": cookie_name[:30],
                "severidade": "MEDIO",
                "descricao": "Cookie sem Secure — transmitido via HTTP!",
            }
        )
    if "samesite" not in lower:
        vulns.append(
            {
                "tipo": "COOKIE_SEM_SAMESITE",
                "cookie": cookie_name[:30],
                "severidade": "MEDIO",
                "descricao": "Cookie sem SameSite — CSRF possível!",
            }
        )
    if "__host-" in lower or "__secure-" in lower:
        if "secure" not in lower or "path=/" not in lower:
            vulns.append(
                {
                    "tipo": "COOKIE_PREFIX_VIOLATION",
                    "severidade": "ALTO",
                    "descricao": "Cookie prefix (__Host-/__Secure-) sem Secure/Path=/!",
                }
            )

    return vulns


def _detect_waf(resp):
    """Detecta WAF/firewall baseado em headers e patterns."""
    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-apigw"],
        "Akamai": ["akamai", "x-akamai"],
        "Imperva": ["incap_ses", "x-cdn: Imperva"],
        "Sucuri": ["sucuri", "x-sucuri-id"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BIG-IP": ["bigipserver", "f5"],
    }
    detected = []
    combined = str(resp.headers).lower() + resp.text[:500].lower()
    for waf, sigs in waf_signatures.items():
        for sig in sigs:
            if sig.lower() in combined:
                detected.append(waf)
                break
    return detected


def run(target, ip, open_ports, banners):
    """
    Tech Fingerprint & Security Headers 2026-Grade.

    Técnicas: 35 tech signatures, 7 JS framework patterns, 11 security headers
    (HSTS analysis: subdomains/max-age/preload), cookie audit (HttpOnly/Secure/
    SameSite/prefix), WAF detection (7 WAFs), X-Powered-By/Server version disclosure.
    """
    _ = (ip, open_ports, banners)
    techs = {}
    sec_headers = {}
    vulns = []
    waf = []

    try:
        resp = requests.get(f"http://{target}/", timeout=8)
        headers = resp.headers

        techs, tech_vulns = _detect_tech(resp, headers)
        vulns.extend(tech_vulns)

        sec_headers, header_vulns = _audit_security_headers(headers)
        vulns.extend(header_vulns)

        vulns.extend(_audit_cookies(headers))

        waf = _detect_waf(resp)

    except Exception as e:
        return {"plugin": "tech_fingerprint", "resultados": {"erro": str(e)}}

    return {
        "plugin": "tech_fingerprint",
        "versao": "2026.1",
        "tecnicas": [
            "tech_signatures",
            "js_frameworks",
            "security_headers",
            "hsts_analysis",
            "cookie_audit",
            "waf_detection",
        ],
        "resultados": {
            "tecnologias": techs,
            "headers_seguranca": sec_headers,
            "waf": waf if waf else "Nenhum WAF detectado",
            "vulns": vulns,
        },
    }
