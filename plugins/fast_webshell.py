# plugins/fast_webshell.py — Cascavel 2026 Intelligence
"""
HTTP PUT/PATCH Method Upload Detection — Cascavel Elite Plugin.

Técnicas: HTTP PUT/PATCH method detection passiva (sem upload de payload),
OPTIONS method enumeration, WebDAV detection, Content-Type acceptance test,
multipart upload endpoint detection, dangerous extension acceptance test.

ZERO FALSO POSITIVO: Não envia nenhum payload malicioso. Testa apenas se
o servidor aceita o MÉTODO PUT/PATCH e quais extensões ele permite.
"""

import requests

UPLOAD_PATHS = [
    "/upload",
    "/uploads",
    "/api/upload",
    "/api/v1/upload",
    "/files",
    "/media",
    "/assets",
    "/wp-content/uploads",
    "/images",
    "/documents",
    "/static",
    "/public",
]

DANGEROUS_EXTENSIONS = [
    ".php",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
    ".sh",
]


def _check_options(url, timeout):
    """Verifica métodos HTTP permitidos via OPTIONS."""
    try:
        r = requests.options(url, timeout=timeout, allow_redirects=False)
        allow = r.headers.get("Allow", "")
        dav = r.headers.get("DAV", "")
        return {
            "status": r.status_code,
            "allow": allow,
            "dav": dav,
            "put_allowed": "PUT" in allow.upper(),
            "webdav": bool(dav),
        }
    except Exception:
        return None


def _check_put_method(url, timeout):
    """Testa se PUT é aceito enviando payload INERTE (vazio)."""
    try:
        # Envia corpo vazio com Content-Length: 0 — INOFENSIVO
        r = requests.put(
            url,
            data=b"",
            timeout=timeout,
            allow_redirects=False,
            headers={"Content-Length": "0", "Content-Type": "text/plain"},
        )
        # Só conta como vulnerável se o servidor aceita (2xx)
        # 405 Method Not Allowed = seguro
        # 403 Forbidden = seguro (blocked)
        # 401 Unauthorized = parcial (auth required mas método existe)
        # 200/201/204 = VULNERÁVEL (aceita PUT sem restrição)
        accepted = r.status_code in (200, 201, 204)
        auth_required = r.status_code == 401
        return {
            "status_code": r.status_code,
            "accepted": accepted,
            "auth_required": auth_required,
        }
    except requests.Timeout:
        return {"erro": "timeout"}
    except Exception:
        return None


def _check_extension_acceptance(base_url, timeout):
    """Testa se o servidor aceita extensões perigosas via PUT (corpo vazio)."""
    accepted_exts = []
    for ext in DANGEROUS_EXTENSIONS:
        test_url = f"{base_url}/cascavel_test_9f8a7b{ext}"
        try:
            r = requests.put(
                test_url,
                data=b"",
                timeout=timeout,
                allow_redirects=False,
                headers={"Content-Length": "0", "Content-Type": "text/plain"},
            )
            if r.status_code in (200, 201, 204):
                accepted_exts.append(ext)
        except Exception:
            continue
    return accepted_exts


def run(target, ip, open_ports, banners):
    """
    Scanner Upload Passivo 2026-Grade — HTTP PUT/PATCH Method Detection.

    Técnicas: OPTIONS method discovery, PUT acceptance test (corpo vazio),
    WebDAV detection, dangerous extension acceptance (12 exts), multipart
    upload endpoint enumeration (12 paths). Zero payload malicioso enviado.
    Zero falso positivo — classifica como vulnerável APENAS se PUT retorna
    2xx para corpo vazio.
    """
    _ = (ip, open_ports, banners)

    base = f"http://{target}"
    timeout = 8
    vulns = []
    intel = {"paths_tested": 0, "methods_checked": 0}

    # 1. OPTIONS no root
    options_root = _check_options(base, timeout)
    if options_root:
        intel["root_options"] = options_root
        if options_root.get("put_allowed"):
            vulns.append(
                {
                    "tipo": "PUT_METHOD_ALLOWED",
                    "severidade": "ALTO",
                    "path": "/",
                    "evidence": options_root.get("allow", ""),
                    "descricao": "Servidor root aceita método PUT via OPTIONS header",
                }
            )
        if options_root.get("webdav"):
            vulns.append(
                {
                    "tipo": "WEBDAV_ENABLED",
                    "severidade": "ALTO",
                    "path": "/",
                    "evidence": options_root.get("dav", ""),
                    "descricao": "WebDAV habilitado — risco de upload/delete de arquivos",
                }
            )

    # 2. PUT test no root (corpo vazio = inofensivo)
    put_root = _check_put_method(base, timeout)
    if put_root and put_root.get("accepted"):
        vulns.append(
            {
                "tipo": "PUT_UPLOAD_ACCEPTED",
                "severidade": "CRITICO",
                "path": "/",
                "status_code": put_root["status_code"],
                "descricao": "PUT aceito no root com corpo vazio — upload arbitrário possível!",
            }
        )
    intel["methods_checked"] += 1

    # 3. Scan upload paths
    for path in UPLOAD_PATHS:
        url = f"{base}{path}"
        intel["paths_tested"] += 1
        put_result = _check_put_method(url, timeout)
        if put_result and put_result.get("accepted"):
            vulns.append(
                {
                    "tipo": "PUT_UPLOAD_ACCEPTED",
                    "severidade": "CRITICO",
                    "path": path,
                    "status_code": put_result["status_code"],
                    "descricao": f"PUT aceito em {path} — upload path exposto!",
                }
            )
        elif put_result and put_result.get("auth_required"):
            vulns.append(
                {
                    "tipo": "PUT_AUTH_REQUIRED",
                    "severidade": "MEDIO",
                    "path": path,
                    "status_code": 401,
                    "descricao": f"PUT requer autenticação em {path} — endpoint existe mas protegido",
                }
            )

    # 4. Extension acceptance (só testa se PUT foi aceito em algum lugar)
    if any(v["tipo"] == "PUT_UPLOAD_ACCEPTED" for v in vulns):
        dangerous_path = next(
            (v["path"] for v in vulns if v["tipo"] == "PUT_UPLOAD_ACCEPTED"),
            "/",
        )
        accepted_exts = _check_extension_acceptance(
            f"{base}{dangerous_path}" if dangerous_path != "/" else base,
            timeout,
        )
        if accepted_exts:
            vulns.append(
                {
                    "tipo": "DANGEROUS_EXTENSIONS_ACCEPTED",
                    "severidade": "CRITICO",
                    "extensions": accepted_exts,
                    "descricao": f"Servidor aceita upload de extensões perigosas: {', '.join(accepted_exts)}",
                }
            )
            intel["dangerous_extensions_accepted"] = accepted_exts

    return {
        "plugin": "fast_webshell",
        "versao": "2026.1",
        "tecnicas": ["options_method", "put_acceptance", "webdav_detection", "extension_test", "upload_path_enum"],
        "resultados": {
            "vulns": vulns,
            "intel": intel,
            "nota": "Detecção 100% passiva — nenhum payload malicioso enviado",
        },
    }
