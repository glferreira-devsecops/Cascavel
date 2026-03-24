# plugins/session_fixation.py — Cascavel 2026 Intelligence
import requests
import math
import re


LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/api/auth/login",
    "/api/v1/auth/login", "/user/login", "/account/login",
    "/api/login", "/api/v1/login", "/admin/login",
]

SESSION_COOKIE_NAMES = [
    "session", "sessionid", "sess", "jsessionid", "phpsessid",
    "connect.sid", "sid", "asp.net_sessionid", "laravel_session",
    "ci_session", "_session_id", "flask_session",
]


def _calculate_entropy(value):
    """Calcula Shannon entropy."""
    if not value:
        return 0
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _get_session_cookie(target, path):
    """Obtém cookies de sessão antes do login."""
    try:
        resp = requests.get(f"http://{target}{path}", timeout=8, allow_redirects=False)
        cookies = resp.cookies.get_dict()
        set_cookie = resp.headers.get("Set-Cookie", "")
        return cookies, set_cookie, resp.status_code
    except Exception:
        return {}, "", 0


def _check_session_rotation(target, path, pre_cookies):
    """Verifica se a sessão é rotacionada após login."""
    try:
        session = requests.Session()
        for name, value in pre_cookies.items():
            session.cookies.set(name, value)
        resp = session.post(
            f"http://{target}{path}",
            data={"username": "test", "password": "test"},
            timeout=8, allow_redirects=False,
        )
        post_cookies = session.cookies.get_dict()
        return post_cookies, resp.status_code
    except Exception:
        return {}, 0


def _analyze_fixation(path, pre_cookies, post_cookies, post_status):
    """Analisa session fixation comparando cookies pre/post login."""
    vulns = []
    if not pre_cookies or post_status == 0:
        return vulns

    for name in pre_cookies:
        if name in post_cookies and pre_cookies[name] == post_cookies[name]:
            vulns.append({
                "tipo": "SESSION_FIXATION", "endpoint": path,
                "cookie": name, "severidade": "CRITICO",
                "descricao": f"Cookie '{name}' não rotacionada após login — session fixation!",
            })
    return vulns


def _check_cookie_flags(set_cookie_header, path):
    """Verifica flags de segurança em cookies de sessão."""
    vulns = []
    if not set_cookie_header:
        return vulns

    for cookie_part in set_cookie_header.split(","):
        lower = cookie_part.lower().strip()
        is_session = any(name in lower for name in SESSION_COOKIE_NAMES)
        if not is_session:
            continue

        if "httponly" not in lower:
            vulns.append({
                "tipo": "SESSION_NO_HTTPONLY", "endpoint": path,
                "severidade": "ALTO",
                "descricao": "Cookie de sessão sem HttpOnly — XSS session theft!",
            })
        if "secure" not in lower:
            vulns.append({
                "tipo": "SESSION_NO_SECURE", "endpoint": path,
                "severidade": "MEDIO",
                "descricao": "Cookie de sessão sem Secure — transmissão HTTP plaintext!",
            })
        if "samesite=none" in lower:
            vulns.append({
                "tipo": "SESSION_SAMESITE_NONE", "endpoint": path,
                "severidade": "ALTO",
                "descricao": "Cookie com SameSite=None — CSRF bypass!",
            })
        elif "samesite" not in lower:
            vulns.append({
                "tipo": "SESSION_NO_SAMESITE", "endpoint": path,
                "severidade": "MEDIO",
                "descricao": "Cookie sem SameSite — default Lax (parcial)",
            })

        # Check path restriction
        if "path=/" in lower and "path=/api" not in lower:
            # Cookie accessible across all paths — broader scope than needed
            pass  # Common, so don't flag

    return vulns


def _check_session_entropy(cookies, path):
    """Verifica entropia dos tokens de sessão."""
    vulns = []
    for name, value in cookies.items():
        name_lower = name.lower()
        if any(sn in name_lower for sn in SESSION_COOKIE_NAMES):
            entropy = _calculate_entropy(value)
            if entropy < 3.5:
                vulns.append({
                    "tipo": "SESSION_LOW_ENTROPY", "endpoint": path,
                    "cookie": name, "entropia": round(entropy, 2),
                    "severidade": "CRITICO",
                    "descricao": f"Session token com entropia baixa ({entropy:.2f}) — previsível!",
                })
            if len(value) < 16:
                vulns.append({
                    "tipo": "SESSION_SHORT_TOKEN", "endpoint": path,
                    "cookie": name, "tamanho": len(value),
                    "severidade": "ALTO",
                    "descricao": f"Session token curto ({len(value)} chars) — brute-force possível!",
                })
    return vulns


def _check_session_predictability(target, path):
    """Coleta múltiplos tokens para detectar padrões sequenciais."""
    tokens = []
    for _ in range(3):
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            for name, value in resp.cookies.items():
                if any(sn in name.lower() for sn in SESSION_COOKIE_NAMES):
                    tokens.append(value)
        except Exception:
            continue

    if len(tokens) >= 2:
        # Check if tokens share common prefix (sequential)
        prefix_len = 0
        for i, char in enumerate(tokens[0]):
            if all(len(t) > i and t[i] == char for t in tokens[1:]):
                prefix_len += 1
            else:
                break
        if prefix_len > len(tokens[0]) * 0.7:
            return {
                "tipo": "SESSION_SEQUENTIAL", "endpoint": path,
                "prefix_comum": tokens[0][:prefix_len],
                "severidade": "CRITICO",
                "descricao": "Session tokens com prefixo sequencial — prediction attack!",
            }
    return None


def _check_session_logout(target):
    """Verifica se logout invalida a sessão."""
    vulns = []
    # Get a session
    try:
        session = requests.Session()
        session.get(f"http://{target}/login", timeout=5)
        pre_cookies = dict(session.cookies)

        # Attempt logout
        for logout_path in ["/logout", "/signout", "/api/logout", "/api/auth/logout"]:
            session.get(f"http://{target}{logout_path}", timeout=5)
            session.post(f"http://{target}{logout_path}", timeout=5)

        # Check if old session still works
        for check_path in ["/profile", "/dashboard", "/api/me", "/api/v1/me"]:
            resp = requests.get(
                f"http://{target}{check_path}", timeout=5,
                cookies=pre_cookies,
            )
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["email", "username", "profile"]):
                vulns.append({
                    "tipo": "SESSION_NOT_INVALIDATED", "severidade": "ALTO",
                    "descricao": "Sessão não invalidada após logout — session riding!",
                })
                break
    except Exception:
        pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Session Management 2026-Grade — Fixation, Entropy, Flags, Predictability.

    Técnicas: Session fixation detection (pre/post login cookie comparison),
    cookie security flags (HttpOnly/Secure/SameSite), Shannon entropy analysis,
    token length check, sequential token detection, logout invalidation check,
    12 session cookie name patterns, 10 login paths.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for path in LOGIN_PATHS:
        pre_cookies, set_cookie, status = _get_session_cookie(target, path)
        if status in (200, 302, 301):
            # Cookie flags
            vulns.extend(_check_cookie_flags(set_cookie, path))

            # Session rotation
            post_cookies, post_status = _check_session_rotation(target, path, pre_cookies)
            vulns.extend(_analyze_fixation(path, pre_cookies, post_cookies, post_status))

            # Session entropy
            vulns.extend(_check_session_entropy(pre_cookies, path))

            # Session predictability
            pred = _check_session_predictability(target, path)
            if pred:
                vulns.append(pred)

    # Logout invalidation
    vulns.extend(_check_session_logout(target))

    return {
        "plugin": "session_fixation",
        "versao": "2026.1",
        "tecnicas": ["fixation", "cookie_flags", "entropy_analysis",
                      "predictability", "sequential_detection", "logout_invalidation"],
        "resultados": vulns if vulns else "Nenhuma falha de sessão detectada",
    }
