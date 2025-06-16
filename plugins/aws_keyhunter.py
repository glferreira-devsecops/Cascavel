# plugins/aws_keys_hunter.py
def run(target, ip, open_ports, banners):
    """
    Procura por chaves AWS expostas em arquivos comuns no servidor web.
    Retorna os caminhos onde encontrou possíveis credenciais e amostra do conteúdo.
    """
    import requests
    import re

    paths = ["/.env", "/config.php", "/config.json", "/.aws/credentials"]
    encontrados = []

    for path in paths:
        try:
            url = f"http://{target}{path}"
            resp = requests.get(url, timeout=7)
            txt = resp.text.lower()
            if "aws_access_key_id" in txt or "aws_secret_access_key" in txt:
                key_match = re.findall(r'AKIA[0-9A-Z]{16}', resp.text)
                encontrados.append({
                    "path": path,
                    "chaves": key_match,
                    "amostra": resp.text[:200]
                })
        except Exception:
            pass

    return {
        "plugin": "aws_keys_hunter",
        "resultados": encontrados if encontrados else "Nenhuma chave AWS encontrada"
    }
