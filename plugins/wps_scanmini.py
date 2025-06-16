# plugins/wpscan_mini.py
def run(target, results):
    """
    Mini WordPress scan: detecta endpoints típicos, retorna lista.
    """
    import requests
    endpoints = [
        "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/.git/config",
        "/wp-content/", "/wp-includes/", "/license.txt", "/readme.html"
    ]
    encontrados = []
    for ep in endpoints:
        try:
            url = f"http://{target}{ep}"
            r = requests.get(url, timeout=8)
            if r.status_code in [200, 401, 403]:
                encontrados.append({
                    "endpoint": ep,
                    "status": r.status_code
                })
        except Exception:
            continue
    results["wpscan_mini"] = encontrados if encontrados else "Nenhum endpoint WordPress típico detectado."
