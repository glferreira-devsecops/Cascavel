# plugins/wps_scanmini.py
import requests


def run(target, ip, open_ports, banners):
    """
    Mini WordPress scan: detecta endpoints típicos e extrai informações.
    """
    _ = (ip, open_ports, banners)

    endpoints = [
        "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/.git/config",
        "/wp-content/", "/wp-includes/", "/license.txt", "/readme.html",
        "/wp-json/wp/v2/users", "/wp-json/", "/wp-cron.php",
    ]
    encontrados = []

    for ep in endpoints:
        try:
            url = f"http://{target}{ep}"
            r = requests.get(url, timeout=8, allow_redirects=False)
            if r.status_code in [200, 301, 302, 401, 403]:
                info = {"endpoint": ep, "status": r.status_code}
                if "wp/v2/users" in ep and r.status_code == 200:
                    try:
                        users = [u.get("slug", "") for u in r.json()[:5]]
                        info["usuarios"] = users
                    except Exception:
                        pass
                encontrados.append(info)
        except Exception:
            continue

    return {
        "plugin": "wps_scanmini",
        "resultados": encontrados if encontrados else "Nenhum endpoint WordPress típico detectado.",
    }
