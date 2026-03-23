# plugins/tech_fingerprint.py
def run(target, ip, open_ports, banners):
    """
    Realiza fingerprint tecnológico básico via headers HTTP.
    Captura informações sobre servidor, tecnologias e headers de segurança expostos.
    """
    import requests

    resultado = {}
    try:
        resposta = requests.get(f"http://{target}", timeout=7, allow_redirects=True)
        headers = resposta.headers

        resultado["server"] = headers.get("server", "desconhecido")
        resultado["x-powered-by"] = headers.get("x-powered-by", "desconhecido")

        # Headers de segurança
        security_headers = {
            "x-frame-options": headers.get("x-frame-options"),
            "x-content-type-options": headers.get("x-content-type-options"),
            "strict-transport-security": headers.get("strict-transport-security"),
            "content-security-policy": headers.get("content-security-policy"),
            "x-xss-protection": headers.get("x-xss-protection"),
            "referrer-policy": headers.get("referrer-policy"),
        }
        resultado["security_headers"] = {k: v for k, v in security_headers.items() if v}
        resultado["security_headers_ausentes"] = [k for k, v in security_headers.items() if not v]

        # Extras
        x_asp = headers.get("x-aspnet-version")
        if x_asp:
            resultado["x-aspnet-version"] = x_asp

        resultado["cookies"] = [
            {"name": c.name, "secure": c.secure, "httponly": "httponly" in str(c._rest).lower()}
            for c in resposta.cookies
        ]

    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "tech_fingerprint", "resultados": resultado}
