# plugins/http_methods.py
import requests


def run(target, ip, open_ports, banners):
    """
    Audita métodos HTTP disponíveis no servidor.
    Detecta métodos perigosos: PUT, DELETE, TRACE, CONNECT, PATCH.
    """
    _ = (ip, open_ports, banners)

    metodos = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"]
    perigosos = {"PUT", "DELETE", "TRACE", "CONNECT"}
    paths = ["/", "/api/", "/admin/", "/upload/"]
    resultados = []

    for path in paths:
        url = f"http://{target}{path}"
        metodos_aceitos = []

        try:
            resp = requests.options(url, timeout=5)
            allow = resp.headers.get("Allow", "")
            if allow:
                metodos_aceitos = [m.strip().upper() for m in allow.split(",")]
        except Exception:
            pass

        if not metodos_aceitos:
            for metodo in metodos:
                try:
                    resp = requests.request(metodo, url, timeout=4)
                    if resp.status_code not in [405, 501, 400]:
                        metodos_aceitos.append(metodo)
                except Exception:
                    continue

        if metodos_aceitos:
            achados_perigosos = [m for m in metodos_aceitos if m in perigosos]
            resultados.append({
                "path": path,
                "metodos_aceitos": metodos_aceitos,
                "perigosos": achados_perigosos if achados_perigosos else None,
                "severidade": "ALTO" if achados_perigosos else "INFO",
            })

    return {
        "plugin": "http_methods",
        "resultados": resultados if resultados else "Nenhum método HTTP perigoso detectado",
    }
