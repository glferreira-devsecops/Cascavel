# plugins/param_miner.py
def run(target, ip, open_ports, banners):
    """
    Parameter Mining / Hidden Parameter Discovery.
    Descobre parâmetros GET ocultos que podem revelar funcionalidades escondidas.
    Baseado em Param Miner (PortSwigger).
    """
    import requests

    hidden_params = [
        "debug", "test", "admin", "internal", "dev", "staging", "verbose",
        "trace", "callback", "jsonp", "format", "output", "type", "mode",
        "action", "method", "func", "handler", "token", "key", "secret",
        "api_key", "apikey", "access_token", "auth", "session", "role",
        "user", "uid", "id", "config", "settings", "env", "version",
        "v", "lang", "locale", "redirect", "return", "next", "url",
        "file", "path", "include", "template", "view", "source",
        "preview", "draft", "unpublished", "hidden", "private",
    ]
    pages = ["/", "/api/", "/api/v1/", "/admin/", "/login"]
    resultado = {"params_descobertos": []}

    for page in pages:
        # Baseline
        baseline_url = f"http://{target}{page}"
        try:
            baseline = requests.get(baseline_url, timeout=5)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            continue

        for param in hidden_params:
            url = f"http://{target}{page}?{param}=1"
            try:
                resp = requests.get(url, timeout=4)
                diff = abs(len(resp.text) - baseline_len)

                # Parâmetro causa mudança significativa
                if diff > 50 or resp.status_code != baseline_status:
                    entry = {
                        "pagina": page,
                        "parametro": param,
                        "diff_tamanho": diff,
                        "status_baseline": baseline_status,
                        "status_param": resp.status_code,
                    }

                    if param in ["debug", "trace", "verbose", "dev", "internal"]:
                        entry["severidade"] = "ALTO"
                        entry["tipo"] = "DEBUG_PARAM"
                    elif param in ["admin", "role", "secret", "token", "key", "api_key"]:
                        entry["severidade"] = "ALTO"
                        entry["tipo"] = "SENSITIVE_PARAM"
                    elif param in ["file", "path", "include", "template"]:
                        entry["severidade"] = "MEDIO"
                        entry["tipo"] = "INJECTION_SURFACE"
                    else:
                        entry["severidade"] = "BAIXO"
                        entry["tipo"] = "HIDDEN_PARAM"

                    resultado["params_descobertos"].append(entry)
            except Exception:
                continue

    total = len(resultado["params_descobertos"])
    return {
        "plugin": "param_miner",
        "resultados": resultado if total > 0 else "Nenhum parâmetro oculto descoberto"
    }
