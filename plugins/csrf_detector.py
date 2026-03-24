# plugins/csrf_detector.py — Cascavel 2026 Intelligence
import math
import re

import requests

PAGES = [
    "/",
    "/login",
    "/register",
    "/contact",
    "/settings",
    "/profile",
    "/admin",
    "/account",
    "/api/",
    "/password/reset",
    "/payment",
    "/checkout",
    "/transfer",
    "/delete-account",
    "/api/settings",
]

CSRF_TOKEN_NAMES = [
    "csrf",
    "csrftoken",
    "csrf_token",
    "_csrf",
    "xsrf",
    "xsrf-token",
    "authenticity_token",
    "__requestverificationtoken",
    "csrfmiddlewaretoken",
    "antiforgerytoken",
    "_token",
    "csrf-token",
    "x-csrf-token",
]

SENSITIVE_ACTIONS = [
    "password",
    "delete",
    "transfer",
    "payment",
    "admin",
    "settings",
    "update",
    "email",
    "phone",
    "role",
]


def _calculate_entropy(token_value):
    """Calcula Shannon entropy de um token."""
    if not token_value:
        return 0
    freq = {}
    for char in token_value:
        freq[char] = freq.get(char, 0) + 1
    length = len(token_value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _analyze_forms(resp_text, page):
    """Analisa formulários HTML para ausência de CSRF tokens."""
    vulns = []
    forms = re.findall(r"<form[^>]*>(.*?)</form>", resp_text, re.DOTALL | re.IGNORECASE)

    for i, form in enumerate(forms):
        form_lower = form.lower()
        # Only check POST forms
        if 'method="post"' not in form_lower and "method='post'" not in form_lower:
            continue

        has_csrf = any(token_name in form_lower for token_name in CSRF_TOKEN_NAMES)
        action = re.search(r'action=["\']([^"\']+)', form, re.IGNORECASE)
        action_url = action.group(1) if action else "N/A"

        # Check if form performs sensitive action
        is_sensitive = any(act in form_lower or act in str(action_url).lower() for act in SENSITIVE_ACTIONS)

        if not has_csrf:
            vulns.append(
                {
                    "tipo": "CSRF_FORM_SEM_TOKEN",
                    "pagina": page,
                    "form_index": i,
                    "action": action_url,
                    "severidade": "CRITICO" if is_sensitive else "ALTO",
                    "descricao": f"Formulário POST sem CSRF token{' (ação sensível!)' if is_sensitive else ''}",
                }
            )
        else:
            # Check token entropy
            token_match = re.search(
                r'(?:csrf|_token|xsrf)[^"\']*["\'][^"\']*value=["\']([^"\']+)',
                form,
                re.IGNORECASE,
            )
            if token_match:
                token_val = token_match.group(1)
                entropy = _calculate_entropy(token_val)
                if entropy < 3.5:
                    vulns.append(
                        {
                            "tipo": "CSRF_TOKEN_LOW_ENTROPY",
                            "pagina": page,
                            "entropia": round(entropy, 2),
                            "severidade": "ALTO",
                            "descricao": f"CSRF token com entropia baixa ({entropy:.2f}) — previsível!",
                        }
                    )
                if len(token_val) < 16:
                    vulns.append(
                        {
                            "tipo": "CSRF_TOKEN_SHORT",
                            "pagina": page,
                            "tamanho": len(token_val),
                            "severidade": "ALTO",
                            "descricao": f"CSRF token curto ({len(token_val)} chars) — brute-force possível!",
                        }
                    )

    return vulns


def _analyze_cookies(resp, page):
    """Analisa cookies de sessão para flags de segurança."""
    vulns = []
    set_cookies = resp.headers.get("Set-Cookie", "")
    if not set_cookies:
        return vulns

    for cookie_part in set_cookies.split(","):
        lower = cookie_part.lower().strip()
        is_session = any(name in lower for name in ["session", "sess_", "jsessionid", "phpsessid", "connect.sid"])
        if not is_session:
            continue

        if "samesite=none" in lower:
            vulns.append(
                {
                    "tipo": "COOKIE_SAMESITE_NONE",
                    "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Session cookie com SameSite=None — CSRF bypass direto!",
                }
            )
        elif "samesite" not in lower:
            vulns.append(
                {
                    "tipo": "COOKIE_SEM_SAMESITE",
                    "pagina": page,
                    "severidade": "MEDIO",
                    "descricao": "Session cookie sem SameSite — default Lax (parcial)",
                }
            )

        if "httponly" not in lower:
            vulns.append(
                {
                    "tipo": "COOKIE_SEM_HTTPONLY",
                    "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Session cookie sem HttpOnly — XSS session theft!",
                }
            )

        if "secure" not in lower:
            vulns.append(
                {
                    "tipo": "COOKIE_SEM_SECURE",
                    "pagina": page,
                    "severidade": "MEDIO",
                    "descricao": "Session cookie sem Secure — transmissão HTTP plaintext!",
                }
            )

    return vulns


def _check_json_csrf(target, page):
    """Testa se endpoints aceitam JSON sem CSRF — vulnerável via fetch/sendBeacon."""
    vulns = []
    try:
        # Test with text/plain content-type (bypasses preflight)
        resp = requests.post(
            f"http://{target}{page}",
            data='{"test": "csrf"}',
            headers={"Content-Type": "text/plain"},
            timeout=5,
        )
        if resp.status_code in (200, 201, 204):
            vulns.append(
                {
                    "tipo": "JSON_CSRF_TEXT_PLAIN",
                    "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Endpoint aceita JSON via Content-Type text/plain — JSON CSRF!",
                }
            )
    except Exception:
        pass

    # Test sendBeacon-style (application/x-www-form-urlencoded with JSON body)
    try:
        resp = requests.post(
            f"http://{target}{page}",
            data='{"test":"csrf"}',
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5,
        )
        if resp.status_code in (200, 201, 204):
            vulns.append(
                {
                    "tipo": "JSON_CSRF_FORM_URLENCODED",
                    "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Endpoint aceita JSON via form-urlencoded — sendBeacon CSRF!",
                }
            )
    except Exception:
        pass

    return vulns


def _check_cors_csrf(target):
    """Verifica se CORS misconfiguration permite CSRF cross-origin."""
    try:
        resp = requests.get(f"http://{target}/", headers={"Origin": "https://evil.com"}, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil.com" and acac.lower() == "true":
            return {
                "tipo": "CORS_CSRF_ENABLED",
                "severidade": "CRITICO",
                "descricao": "CORS reflete origin evil.com com credentials — CSRF cross-origin total!",
            }
    except Exception:
        pass
    return None


def _check_referer_validation(target):
    """Testa se Referer header é validado para requests state-changing."""
    vulns = []
    for page in ["/settings", "/profile", "/api/settings"]:
        try:
            # Request sem Referer
            resp_no = requests.post(f"http://{target}{page}", data={"test": "csrf"}, timeout=5, headers={"Referer": ""})
            # Request com Referer evil
            resp_evil = requests.post(
                f"http://{target}{page}", data={"test": "csrf"}, timeout=5, headers={"Referer": "https://evil.com/"}
            )
            if resp_no.status_code in (200, 201, 204) or resp_evil.status_code in (200, 201, 204):
                vulns.append(
                    {
                        "tipo": "CSRF_NO_REFERER_CHECK",
                        "pagina": page,
                        "severidade": "MEDIO",
                        "descricao": "Endpoint não valida Referer — CSRF via Referer bypass!",
                    }
                )
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Detector CSRF 2026-Grade — Forms, Cookies, JSON, CORS, Referer.

    Técnicas: Form analysis com token entropy/length check, SameSite=None detection,
    JSON CSRF via text/plain e form-urlencoded (sendBeacon), CORS-based CSRF,
    Referer validation check, sensitive action detection,
    cookie security flags (HttpOnly/Secure/SameSite).
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for page in PAGES:
        url = f"http://{target}{page}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                continue

            # 1. Form analysis
            vulns.extend(_analyze_forms(resp.text, page))

            # 2. Cookie analysis
            vulns.extend(_analyze_cookies(resp, page))

        except Exception:
            continue

        # 3. JSON CSRF
        vulns.extend(_check_json_csrf(target, page))

    # 4. CORS-based CSRF
    cors = _check_cors_csrf(target)
    if cors:
        vulns.append(cors)

    # 5. Referer validation
    vulns.extend(_check_referer_validation(target))

    return {
        "plugin": "csrf_detector",
        "versao": "2026.1",
        "tecnicas": [
            "form_analysis",
            "token_entropy",
            "samesite_detection",
            "json_csrf",
            "sendbeacon",
            "cors_csrf",
            "referer_bypass",
            "cookie_flags",
        ],
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade CSRF detectada",
    }
