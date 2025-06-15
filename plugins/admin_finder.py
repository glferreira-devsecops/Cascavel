# plugins/admin_finder.py

def run(target, ip, open_ports, banners):
    """
    Busca páginas administrativas comuns no alvo.
    Retorna uma lista de caminhos encontrados com seus status HTTP.
    """
    import requests

    caminhos = [
        "/admin", "/login", "/administrator", "/adm",
        "/admin.php", "/cpanel", "/admin/login", "/painel",
        "/admin1", "/admin2", "/adminarea", "/backend"
    ]

    encontrados = []

    for caminho in caminhos:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}{caminho}"
            try:
                r = requests.get(url, timeout=7, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    encontrados.append({
                        "url": url,
                        "status": r.status_code,
                        "headers": dict(r.headers)
                    })
            except requests.RequestException:
                continue

    return {
        "plugin": "admin_finder",
        "target": target,
        "resultados": (
            encontrados if encontrados else "Nenhuma página admin encontrada"
        )
    }
