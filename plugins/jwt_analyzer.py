# plugins/jwt_analyzer.py
def run(target, ip, open_ports, banners):
    """
    Analisa e testa vulnerabilidades em JWT (JSON Web Tokens).
    2026 Intel: 'Back to the Future' attack (iat manipulation), kid path traversal,
    alg:none, RS256→HS256 confusion, weak secrets, expired tokens aceitos,
    jwk/jku header injection. Ref: RedSentry 2026, SecurityPattern.
    """
    import requests
    import base64
    import json
    import re
    import time

    resultado = {"tokens_encontrados": 0, "vulns": [], "analise": []}

    # 1. Buscar JWT em endpoints
    login_endpoints = ["/api/login", "/api/auth", "/login", "/auth/token",
                       "/oauth/token", "/api/v1/login", "/api/v1/auth",
                       "/api/v1/token", "/api/session", "/signin"]
    test_creds = [
        {"email": "admin@test.com", "password": "admin"},
        {"username": "admin", "password": "admin"},
        {"user": "test", "pass": "test"},
        {"email": "test@test.com", "password": "password"},
    ]

    tokens = set()
    for ep in login_endpoints:
        for cred in test_creds:
            try:
                resp = requests.post(f"http://{target}{ep}", json=cred, timeout=5)
                jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text)
                tokens.update(jwt_matches)
            except Exception:
                continue

    # Buscar em headers e cookies
    try:
        resp = requests.get(f"http://{target}/", timeout=5)
        for val in list(resp.headers.values()) + [str(resp.cookies)]:
            jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', val)
            tokens.update(jwt_matches)
    except Exception:
        pass

    tokens = list(tokens)[:5]
    resultado["tokens_encontrados"] = len(tokens)

    for token in tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            analise = {"header": header, "payload_keys": list(payload.keys())}
            resultado["analise"].append(analise)

            # T1: alg:none
            if header.get("alg", "").lower() in ["none", ""]:
                resultado["vulns"].append({
                    "tipo": "JWT_ALG_NONE", "severidade": "CRITICO",
                    "descricao": "Token usa alg:none — sem assinatura!"
                })

            # T2: Algorithm confusion HS256 + RSA key available
            if header.get("alg") == "HS256":
                resultado["vulns"].append({
                    "tipo": "JWT_WEAK_ALG", "severidade": "MEDIO",
                    "alg": "HS256",
                    "descricao": "HS256 susceptível a brute-force e algorithm confusion (RS256→HS256)"
                })

            # T3: kid path traversal
            if "kid" in header:
                kid = header["kid"]
                if "/" in kid or ".." in kid:
                    resultado["vulns"].append({
                        "tipo": "JWT_KID_PATH_TRAVERSAL", "severidade": "CRITICO",
                        "kid": kid,
                        "descricao": "kid parameter contém path traversal!"
                    })
                resultado["vulns"].append({
                    "tipo": "JWT_KID_PRESENTE", "severidade": "BAIXO",
                    "descricao": "kid presente — testar path traversal manual"
                })

            # T4: jwk/jku header injection
            if "jwk" in header or "jku" in header:
                resultado["vulns"].append({
                    "tipo": "JWT_JWK_INJECTION", "severidade": "CRITICO",
                    "descricao": "jwk/jku no header — possível key injection!"
                })

            # T5: Dados sensíveis no payload
            sensitive = [k for k in payload if k.lower() in
                         ["password", "secret", "ssn", "credit_card", "role",
                          "isadmin", "is_admin", "permissions", "api_key",
                          "private_key", "token"]]
            if sensitive:
                resultado["vulns"].append({
                    "tipo": "JWT_SENSITIVE_DATA", "severidade": "ALTO",
                    "campos": sensitive,
                    "descricao": "Dados sensíveis no payload JWT!"
                })

            # T6: Token expirado
            if "exp" in payload and payload["exp"] < time.time():
                resultado["vulns"].append({
                    "tipo": "JWT_EXPIRED", "severidade": "ALTO",
                    "exp": payload["exp"],
                    "descricao": "Token expirado — testar se servidor aceita"
                })

            # T7: Back to the Future (iat no futuro distante)
            if "iat" in payload and payload["iat"] > time.time() + 86400:
                resultado["vulns"].append({
                    "tipo": "JWT_BACK_TO_FUTURE", "severidade": "ALTO",
                    "iat": payload["iat"],
                    "descricao": "iat no futuro — 'Back to the Future' attack (2026)!"
                })

            # T8: Sem exp (token eterno)
            if "exp" not in payload:
                resultado["vulns"].append({
                    "tipo": "JWT_NO_EXPIRY", "severidade": "MEDIO",
                    "descricao": "Token sem expiração — válido eternamente"
                })

        except Exception:
            continue

    return {"plugin": "jwt_analyzer", "resultados": resultado}
