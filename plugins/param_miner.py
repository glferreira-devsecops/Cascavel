# plugins/param_miner.py
import requests


DEBUG_PARAMS = {"debug", "trace", "verbose", "dev", "internal"}
SENSITIVE_PARAMS = {"admin", "role", "secret", "token", "key", "api_key"}
INJECTION_PARAMS = {"file", "path", "include", "template"}


def run(target, ip, open_ports, banners):
    """
    Parameter Mining / Hidden Parameter Discovery.
    Descobre parâmetros GET ocultos que podem revelar funcionalidades escondidas.
    Baseado em Param Miner (PortSwigger).
    """
    _ = (ip, open_ports, banners)

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

                if diff > 50 or resp.status_code != baseline_status:
                    entry = {
                        "pagina": page, "parametro": param,
                        "diff_tamanho": diff,
                        "status_baseline": baseline_status,
                        "status_param": resp.status_code,
                    }
                    entry["severidade"], entry["tipo"] = _classify_param(param)
                    resultado["params_descobertos"].append(entry)
            except Exception:
                continue

    total = len(resultado["params_descobertos"])
    return {
        "plugin": "param_miner",
        "resultados": resultado if total > 0 else "Nenhum parâmetro oculto descoberto",
    }


def _classify_param(param):
    """Classifica severidade e tipo do parâmetro descoberto."""
    if param in DEBUG_PARAMS:
        return "ALTO", "DEBUG_PARAM"
    if param in SENSITIVE_PARAMS:
        return "ALTO", "SENSITIVE_PARAM"
    if param in INJECTION_PARAMS:
        return "MEDIO", "INJECTION_SURFACE"
    return "BAIXO", "HIDDEN_PARAM"
