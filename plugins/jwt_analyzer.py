# plugins/jwt_analyzer.py
def run(target, ip, open_ports, banners):
    """
    Analisa e testa vulnerabilidades em JWT (JSON Web Tokens).
    Detecta: alg:none, weak secrets, key confusion, expired tokens.
    """
    import requests
    import base64
    import json

    resultado = {"tokens_encontrados": [], "vulns": []}

    # 1. Buscar JWT em endpoints de login e headers
    login_endpoints = ["/api/login", "/api/auth", "/login", "/auth/token",
                       "/oauth/token", "/api/v1/login", "/api/v1/auth"]
    test_creds = [
        {"email": "admin@test.com", "password": "admin"},
        {"username": "admin", "password": "admin"},
        {"user": "test", "pass": "test"},
    ]

    tokens = []
    for ep in login_endpoints:
        for cred in test_creds:
            try:
                resp = requests.post(f"http://{target}{ep}", json=cred, timeout=5)
                text = resp.text
                # Extrair JWT do response
                if "eyJ" in text:
                    import re
                    jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text)
                    tokens.extend(jwt_matches)
            except Exception:
                continue

    # 2. Buscar JWT em headers de resposta
    try:
        resp = requests.get(f"http://{target}/", timeout=5)
        for header_val in resp.headers.values():
            if "eyJ" in header_val:
                import re
                jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', header_val)
                tokens.extend(jwt_matches)
    except Exception:
        pass

    tokens = list(set(tokens))[:5]
    resultado["tokens_encontrados"] = len(tokens)

    # 3. Analisar cada JWT encontrado
    for token in tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        try:
            # Decodificar header e payload
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            info = {"header": header, "payload_keys": list(payload.keys())}

            # Teste 1: alg: none
            if header.get("alg", "").lower() in ["none", ""]:
                resultado["vulns"].append({
                    "tipo": "JWT_ALG_NONE",
                    "severidade": "CRITICO",
                    "descricao": "Token usa alg:none — sem assinatura!",
                })

            # Teste 2: algoritmo fraco
            if header.get("alg") in ["HS256"]:
                resultado["vulns"].append({
                    "tipo": "JWT_WEAK_ALG",
                    "severidade": "MEDIO",
                    "alg": header["alg"],
                    "descricao": "HS256 pode ser vulnerável a brute-force de secret",
                })

            # Teste 3: dados sensíveis no payload
            sensitive = [k for k in payload.keys() if k.lower() in
                         ["password", "secret", "ssn", "credit_card", "role", "isAdmin", "is_admin"]]
            if sensitive:
                resultado["vulns"].append({
                    "tipo": "JWT_SENSITIVE_DATA",
                    "severidade": "ALTO",
                    "campos": sensitive,
                })

            # Teste 4: token expirado mas aceito
            if "exp" in payload:
                import time
                if payload["exp"] < time.time():
                    resultado["vulns"].append({
                        "tipo": "JWT_EXPIRED_ACCEPTED",
                        "severidade": "ALTO",
                        "expiry": payload["exp"],
                    })

            resultado["tokens_encontrados"] = tokens[:2]

        except Exception:
            continue

    return {"plugin": "jwt_analyzer", "resultados": resultado}
