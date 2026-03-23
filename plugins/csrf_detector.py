# plugins/csrf_detector.py
def run(target, ip, open_ports, banners):
    """
    Detector de ausência de proteção CSRF.
    Analisa formulários HTML, headers e cookies para tokens anti-CSRF.
    """
    import requests
    import re

    pages = ["/", "/login", "/register", "/contact", "/settings", "/profile",
             "/admin", "/account", "/api/"]
    resultado = {"forms_sem_csrf": [], "headers_analise": {}}

    csrf_token_names = ["csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
                        "xsrf-token", "authenticity_token", "__requestverificationtoken"]

    for page in pages:
        url = f"http://{target}{page}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                continue

            # 1. Buscar forms sem CSRF token
            forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            for i, form in enumerate(forms):
                has_csrf = False
                for token_name in csrf_token_names:
                    if token_name in form.lower():
                        has_csrf = True
                        break
                if not has_csrf and 'method="post"' in form.lower():
                    action = re.search(r'action=["\']([^"\']+)', form, re.IGNORECASE)
                    resultado["forms_sem_csrf"].append({
                        "pagina": page,
                        "form_index": i,
                        "action": action.group(1) if action else "N/A",
                        "severidade": "ALTO",
                    })

            # 2. Headers anti-CSRF
            for header in ["X-CSRF-Token", "X-XSRF-TOKEN"]:
                if header.lower() in [h.lower() for h in resp.headers]:
                    resultado["headers_analise"]["csrf_header"] = True

            # 3. Cookies SameSite
            for cookie_header in resp.headers.get("Set-Cookie", "").split(","):
                if "samesite" not in cookie_header.lower() and "session" in cookie_header.lower():
                    resultado["forms_sem_csrf"].append({
                        "pagina": page,
                        "tipo": "COOKIE_SEM_SAMESITE",
                        "severidade": "MEDIO",
                        "descricao": "Session cookie sem flag SameSite",
                    })

        except Exception:
            continue

    total = len(resultado["forms_sem_csrf"])
    return {
        "plugin": "csrf_detector",
        "resultados": resultado if total > 0 else "Nenhuma vulnerabilidade CSRF detectada"
    }
