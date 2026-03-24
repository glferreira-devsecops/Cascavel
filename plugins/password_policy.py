# plugins/password_policy.py — Cascavel 2026 Intelligence
import requests
import time


REGISTRATION_PATHS = [
    "/register", "/signup", "/api/register", "/api/v1/register",
    "/api/auth/register", "/api/v1/auth/signup", "/create-account",
    "/api/v2/register", "/api/auth/signup", "/api/users",
]

LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth/login",
    "/api/v1/login", "/api/v1/auth/login",
]

# ──────────── WEAK PASSWORDS (NIST SP 800-63B) ────────────
WEAK_PASSWORDS = [
    ("123456", "NUMERIC_ONLY"),
    ("password", "COMMON_WORD"),
    ("a", "SINGLE_CHAR"),
    ("aaa", "THREE_CHARS"),
    ("aaaa", "FOUR_CHARS"),
    ("abc123", "SIMPLE_COMBO"),
    ("Password1", "BASIC_COMPLEXITY"),
    ("qwerty", "KEYBOARD_PATTERN"),
    ("     ", "WHITESPACE_ONLY"),
    ("test@test.com", "EMAIL_AS_PASSWORD"),
    ("12345678", "EIGHT_NUMERIC"),
    ("password123", "COMMON_APPEND"),
    ("admin", "ADMIN_DEFAULT"),
    ("letmein", "COMMON_PASS"),
    ("iloveyou", "COMMON_PASS_2"),
]

# ──────────── CREDENTIAL STUFFING (Top breached passwords) ────────────
BREACHED_CREDS = [
    ("admin@admin.com", "admin"),
    ("test@test.com", "test123"),
    ("user@example.com", "password"),
    ("admin@example.com", "123456"),
    ("root@localhost", "root"),
]


def _test_password(target, path, password, label):
    """Testa se o endpoint aceita uma senha fraca."""
    try:
        resp = requests.post(
            f"http://{target}{path}",
            json={"email": "cascavel@test.com", "password": password, "username": "cascavel_probe"},
            timeout=8,
        )
        if resp.status_code in (200, 201):
            return {
                "tipo": f"WEAK_PASSWORD_{label}", "endpoint": path,
                "senha_testada": password if len(password) <= 6 else password[:3] + "***",
                "severidade": "ALTO",
                "descricao": f"Senha fraca aceita ({label}) — policy insuficiente!",
            }
        if resp.status_code == 422 and "password" not in resp.text.lower():
            return {
                "tipo": f"PASSWORD_NO_VALIDATION_{label}", "endpoint": path,
                "severidade": "MEDIO",
                "descricao": "422 sem menção a password — validação parcial",
            }
    except Exception:
        pass
    return None


def _check_rate_limit_registration(target, path):
    """Verifica rate limiting no endpoint de registro."""
    try:
        for _ in range(15):
            resp = requests.post(
                f"http://{target}{path}",
                json={"email": "test@test.com", "password": "test"},
                timeout=3,
            )
            if resp.status_code == 429:
                return None
        return {
            "tipo": "REGISTRATION_NO_RATE_LIMIT", "endpoint": path,
            "severidade": "MEDIO",
            "descricao": "Sem rate limit no registro — enumeration/abuse possível!",
        }
    except Exception:
        return None


def _check_rate_limit_login(target, path):
    """Verifica rate limiting no endpoint de login."""
    blocked = False
    try:
        for i in range(20):
            resp = requests.post(
                f"http://{target}{path}",
                json={"email": "brute@test.com", "password": f"wrong{i}"},
                timeout=3,
            )
            if resp.status_code == 429:
                blocked = True
                break
        if not blocked:
            return {
                "tipo": "LOGIN_NO_RATE_LIMIT", "endpoint": path,
                "severidade": "ALTO",
                "descricao": "Sem rate limit no login — brute-force/credential stuffing possível!",
            }
    except Exception:
        pass
    return None


def _check_rate_limit_bypass(target, path):
    """Testa bypass de rate limiting via header rotation."""
    bypass_headers = [
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-For": "10.0.0.2"},
        {"X-Real-IP": "192.168.1.1"},
        {"X-Originating-IP": "172.16.0.1"},
        {"X-Client-IP": "8.8.8.8"},
        {"True-Client-IP": "1.1.1.1"},
    ]
    vulns = []
    for headers in bypass_headers:
        try:
            success_count = 0
            for _ in range(5):
                resp = requests.post(
                    f"http://{target}{path}",
                    json={"email": "bypass@test.com", "password": "wrong"},
                    timeout=3, headers=headers,
                )
                if resp.status_code != 429:
                    success_count += 1
            if success_count == 5:
                vulns.append({
                    "tipo": "RATE_LIMIT_BYPASS", "endpoint": path,
                    "header": list(headers.keys())[0],
                    "severidade": "ALTO",
                    "descricao": f"Rate limit bypass via {list(headers.keys())[0]}!",
                })
                break
        except Exception:
            continue
    return vulns


def _check_credential_stuffing(target, path):
    """Testa credenciais breached comuns."""
    vulns = []
    for email, password in BREACHED_CREDS:
        try:
            resp = requests.post(
                f"http://{target}{path}",
                json={"email": email, "password": password, "username": email.split("@")[0]},
                timeout=5,
            )
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "session", "dashboard", "welcome"]):
                vulns.append({
                    "tipo": "CREDENTIAL_STUFFING_SUCCESS", "endpoint": path,
                    "email": email, "severidade": "CRITICO",
                    "descricao": f"Login com credenciais breached ({email}) — conta comprometida!",
                })
        except Exception:
            continue
    return vulns


def _check_username_enumeration(target, path):
    """Testa se o endpoint vaza informação de existência de usuário."""
    try:
        r_valid = requests.post(
            f"http://{target}{path}",
            json={"email": "admin@admin.com", "password": "wrongpass"},
            timeout=5,
        )
        r_invalid = requests.post(
            f"http://{target}{path}",
            json={"email": "nonexistent_cascavel_probe@test.com", "password": "wrongpass"},
            timeout=5,
        )
        if r_valid.status_code != r_invalid.status_code or len(r_valid.text) != len(r_invalid.text):
            return {
                "tipo": "USERNAME_ENUMERATION", "endpoint": path,
                "severidade": "MEDIO",
                "descricao": "Respostas diferentes para email válido vs. inválido — enumeration!",
            }
        if r_valid.elapsed.total_seconds() - r_invalid.elapsed.total_seconds() > 0.5:
            return {
                "tipo": "USERNAME_ENUMERATION_TIMING", "endpoint": path,
                "severidade": "MEDIO",
                "descricao": "Timing difference para email válido vs. inválido — timing enumeration!",
            }
    except Exception:
        pass
    return None


def _check_password_reset(target):
    """Verifica vulnerabilidades no fluxo de password reset."""
    vulns = []
    reset_paths = ["/reset-password", "/forgot-password", "/api/auth/reset-password",
                    "/api/v1/auth/forgot-password", "/password/reset"]

    for path in reset_paths:
        try:
            # Test rate limit on reset
            for _ in range(10):
                resp = requests.post(
                    f"http://{target}{path}",
                    json={"email": "test@test.com"},
                    timeout=5,
                )
                if resp.status_code == 429:
                    break
            else:
                vulns.append({
                    "tipo": "RESET_NO_RATE_LIMIT", "endpoint": path,
                    "severidade": "MEDIO",
                    "descricao": "Sem rate limit no password reset — email bombing!",
                })

            # Test host header injection on reset
            resp = requests.post(
                f"http://{target}{path}",
                json={"email": "test@test.com"},
                headers={"Host": "evil.com"},
                timeout=5,
            )
            if resp.status_code in (200, 302):
                vulns.append({
                    "tipo": "RESET_HOST_INJECTION", "endpoint": path,
                    "severidade": "ALTO",
                    "descricao": "Password reset aceita Host header injection — token theft!",
                })
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Password Policy 2026-Grade — NIST 800-63B, Credential Stuffing, Rate Limit.

    Técnicas: 15 weak passwords (NIST SP 800-63B), credential stuffing (top breached),
    rate limit check (login + registration), rate limit bypass (header rotation),
    username enumeration (response + timing diff), password reset abuse
    (rate limit + host header injection), 10 registration + 6 login endpoints.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # 1. Weak passwords on registration
    for path in REGISTRATION_PATHS:
        for password, label in WEAK_PASSWORDS:
            vuln = _test_password(target, path, password, label)
            if vuln:
                vulns.append(vuln)
        rate_vuln = _check_rate_limit_registration(target, path)
        if rate_vuln:
            vulns.append(rate_vuln)

    # 2. Login rate limiting
    for path in LOGIN_PATHS:
        rate_vuln = _check_rate_limit_login(target, path)
        if rate_vuln:
            vulns.append(rate_vuln)

        # Rate limit bypass
        vulns.extend(_check_rate_limit_bypass(target, path))

        # Credential stuffing
        vulns.extend(_check_credential_stuffing(target, path))

        # Username enumeration
        enum_vuln = _check_username_enumeration(target, path)
        if enum_vuln:
            vulns.append(enum_vuln)

    # 3. Password reset abuse
    vulns.extend(_check_password_reset(target))

    return {
        "plugin": "password_policy",
        "versao": "2026.1",
        "tecnicas": ["weak_password", "credential_stuffing", "rate_limit",
                      "rate_limit_bypass", "username_enumeration",
                      "timing_enumeration", "password_reset_abuse",
                      "host_header_injection"],
        "resultados": vulns if vulns else "Password policy adequada",
    }
