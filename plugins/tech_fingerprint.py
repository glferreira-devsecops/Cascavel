# plugins/tech_fingerprint.py
def run(target, results):
    """
    Realiza fingerprint tecnológico básico via headers HTTP.
    Captura informações sobre servidor e tecnologias expostas.
    """
    import requests

    try:
        resposta = requests.get(f"http://{target}", timeout=7)
        server = resposta.headers.get('server', 'desconhecido')
        x_powered = resposta.headers.get('x-powered-by', 'desconhecido')
        x_asp = resposta.headers.get('x-aspnet-version', None)
        headers_info = {
            "server": server,
            "x-powered-by": x_powered
        }
        if x_asp:
            headers_info["x-aspnet-version"] = x_asp
        results["tech_fingerprint"] = headers_info
    except Exception as e:
        results["tech_fingerprint"] = {"erro": str(e)}
