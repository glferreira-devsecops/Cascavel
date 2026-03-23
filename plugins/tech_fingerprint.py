# plugins/tech_fingerprint.py
def run(target, ip, open_ports, banners):
    """
    Fingerprinting de tecnologias e security headers audit.
    2026 Intel: OWASP 2025 A02 (Security Misconfiguration #2),
    Supply chain risk headers, Permissions-Policy, COEP, COOP.
    """
    import requests

    resultado = {"tecnologias": {}, "headers_seguranca": {}, "vulns": []}

    try:
        resp = requests.get(f"http://{target}/", timeout=8)
        headers = resp.headers

        # Tech detection
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        via = headers.get("Via", "")

        if server:
            resultado["tecnologias"]["server"] = server
        if powered:
            resultado["tecnologias"]["x_powered_by"] = powered
            resultado["vulns"].append({
                "tipo": "INFO_DISCLOSURE_HEADER", "header": "X-Powered-By",
                "valor": powered, "severidade": "BAIXO",
                "descricao": "X-Powered-By expõe stack — remover em produção"
            })
        if via:
            resultado["tecnologias"]["via"] = via

        # Framework detection from response
        tech_signatures = {
            "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
            "PHP": ["PHPSESSID", "X-Powered-By: PHP"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Rails": ["_rails_session", "X-Runtime"],
            "Spring": ["JSESSIONID", "X-Application-Context"],
            "Express": ["connect.sid", "X-Powered-By: Express"],
            "Next.js": ["__next", "_next/static", "__NEXT_DATA__"],
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
            "Flask": ["session=", "Werkzeug"],
            "WordPress": ["wp-content", "wp-json", "wp-includes"],
            "React": ["_reactRoot", "data-reactroot", "__NEXT"],
            "Angular": ["ng-app", "ng-controller", "angular"],
            "Vue.js": ["data-v-", "__vue__", "vue-router"],
        }
        for tech, indicators in tech_signatures.items():
            for ind in indicators:
                if ind.lower() in resp.text.lower() or ind.lower() in str(headers).lower():
                    resultado["tecnologias"][tech] = True
                    break

        # Security Headers Audit (2026 best practices)
        sec_headers = {
            "Strict-Transport-Security": ("HSTS", "ALTO"),
            "Content-Security-Policy": ("CSP", "ALTO"),
            "X-Content-Type-Options": ("XCTO", "MEDIO"),
            "X-Frame-Options": ("XFO", "MEDIO"),
            "X-XSS-Protection": ("X-XSS", "BAIXO"),
            "Referrer-Policy": ("REFERRER", "BAIXO"),
            "Permissions-Policy": ("PERMISSIONS", "MEDIO"),
            "Cross-Origin-Embedder-Policy": ("COEP", "BAIXO"),
            "Cross-Origin-Opener-Policy": ("COOP", "BAIXO"),
            "Cross-Origin-Resource-Policy": ("CORP", "BAIXO"),
            "Cache-Control": ("CACHE", "BAIXO"),
        }

        ausentes = []
        for header, (label, sev) in sec_headers.items():
            val = headers.get(header, "")
            if val:
                resultado["headers_seguranca"][label] = val[:100]
            else:
                ausentes.append(label)
                if sev in ["ALTO", "MEDIO"]:
                    resultado["vulns"].append({
                        "tipo": "HEADER_AUSENTE", "header": header,
                        "label": label, "severidade": sev,
                    })

        resultado["headers_seguranca"]["ausentes"] = ausentes

        # Cookie security
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                resultado["vulns"].append({
                    "tipo": "COOKIE_SEM_HTTPONLY", "severidade": "ALTO",
                })
            if "secure" not in cookies.lower():
                resultado["vulns"].append({
                    "tipo": "COOKIE_SEM_SECURE", "severidade": "MEDIO",
                })
            if "samesite" not in cookies.lower():
                resultado["vulns"].append({
                    "tipo": "COOKIE_SEM_SAMESITE", "severidade": "MEDIO",
                })

    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "tech_fingerprint", "resultados": resultado}
