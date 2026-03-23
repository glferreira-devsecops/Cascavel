# plugins/clickjacking_check.py
def run(target, ip, open_ports, banners):
    """
    Verifica proteção contra Clickjacking.
    Testa X-Frame-Options e Content-Security-Policy frame-ancestors.
    """
    import requests

    pages = ["/", "/login", "/admin", "/dashboard", "/settings", "/profile"]
    vulns = []

    for page in pages:
        url = f"http://{target}{page}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                continue

            xfo = resp.headers.get("X-Frame-Options", "").upper()
            csp = resp.headers.get("Content-Security-Policy", "")

            has_xfo = xfo in ["DENY", "SAMEORIGIN"]
            has_csp_frame = "frame-ancestors" in csp

            if not has_xfo and not has_csp_frame:
                vulns.append({
                    "tipo": "CLICKJACKING_VULNERAVEL",
                    "pagina": page,
                    "severidade": "MEDIO",
                    "x_frame_options": xfo or "AUSENTE",
                    "csp_frame_ancestors": "AUSENTE",
                    "descricao": "Página pode ser carregada em iframe — possível clickjacking",
                })
            elif xfo == "ALLOWFROM":
                vulns.append({
                    "tipo": "CLICKJACKING_ALLOW_FROM",
                    "pagina": page,
                    "severidade": "BAIXO",
                    "descricao": "ALLOW-FROM é deprecated e não suportado em browsers modernos",
                })

        except Exception:
            continue

    return {"plugin": "clickjacking_check", "resultados": vulns if vulns else "Proteção contra clickjacking presente"}
