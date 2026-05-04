# plugins/web_cache_poison.py — Cascavel 2026 Intelligence
import random
import string
import time

import requests

CANARY = "cascavel-cache-" + "".join(random.choices(string.ascii_lowercase, k=6))
PAGES = [
    "/",
    "/index.html",
    "/about",
    "/home",
    "/login",
    "/api/",
    "/static/",
    "/assets/",
    "/js/app.js",
    "/css/style.css",
]

# ──────────── UNKEYED HEADERS ────────────
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", CANARY, "XFH"),
    ("X-Host", CANARY, "X_HOST"),
    ("X-Original-URL", f"/{CANARY}", "X_ORIGINAL_URL"),
    ("X-Rewrite-URL", f"/{CANARY}", "X_REWRITE_URL"),
    ("X-Forwarded-Scheme", "nothttps", "XFS"),
    ("X-Forwarded-Proto", "nothttps", "XFP"),
    ("X-Forwarded-Port", "1337", "XF_PORT"),
    ("X-Forwarded-Prefix", f"/{CANARY}", "XF_PREFIX"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "XCI_AUTH"),
    ("X-Originating-IP", "127.0.0.1", "XOI"),
    # 2026 additions
    ("X-Forwarded-For", CANARY, "XFF_REFLECTION"),
    ("Transfer-Encoding", "chunked", "TE_UNKEYED"),
    ("X-HTTP-Method-Override", "POST", "METHOD_OVERRIDE"),
    ("X-Amz-Website-Redirect-Location", f"https://{CANARY}.com", "S3_REDIRECT"),
    ("Forwarded", f"host={CANARY}", "RFC7239"),
]


def _verify_waf_blind_reflection(target, page):
    """Verifica se o servidor reflete QUALQUER header unkeyed cegamente."""
    junk_header = "X-Cascavel-Test-Junk"
    junk_value = "cascavel_blind_reflection_" + "".join(random.choices(string.ascii_lowercase, k=6))
    url = f"http://{target}{page}"
    try:
        resp = requests.get(url, headers={junk_header: junk_value}, timeout=5)
        if junk_value in resp.text or junk_value in str(resp.headers):
            return True
        return False
    except Exception:
        return False


def _test_unkeyed_reflection(target, page):
    """Testa se headers unkeyed são refletidos na resposta."""
    vulns = []

    # Se o servidor reflete qualquer header lixo, ignora teste para evitar FPs
    if _verify_waf_blind_reflection(target, page):
        return []

    url = f"http://{target}{page}"
    for header_name, header_value, method in UNKEYED_HEADERS:
        try:
            resp = requests.get(url, headers={header_name: header_value}, timeout=5)
            reflected_text = CANARY in resp.text
            reflected_header = CANARY in str(resp.headers)

            if reflected_text or reflected_header:
                # Verify if cached
                time.sleep(0.5)
                resp2 = requests.get(url, timeout=5)
                if CANARY in resp2.text or CANARY in str(resp2.headers):
                    vulns.append(
                        {
                            "tipo": "WEB_CACHE_POISONING_CONFIRMADO",
                            "pagina": page,
                            "header": header_name,
                            "metodo": method,
                            "severidade": "CRITICO",
                            "descricao": "Cache envenenado — payload persistiu em request sem header!",
                        }
                    )
                else:
                    vulns.append(
                        {
                            "tipo": "UNKEYED_HEADER_REFLECTED",
                            "pagina": page,
                            "header": header_name,
                            "metodo": method,
                            "severidade": "ALTO",
                            "descricao": f"Header {header_name} refletido — cache poisoning possível",
                        }
                    )
                break
        except Exception:
            continue
    return vulns


def _test_cache_deception(target):
    """Testa Web Cache Deception (WCD) attack."""
    vulns = []
    deception_paths = [
        "/account/settings/nonexistent.css",
        "/api/me/fake.js",
        "/profile/test.png",
        "/dashboard/fake.woff2",
        "/user/info/style.css",
    ]
    for path in deception_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            cache_control = resp.headers.get("Cache-Control", "")
            age = resp.headers.get("Age", "")
            x_cache = resp.headers.get("X-Cache", "")

            if resp.status_code == 200:
                if "HIT" in x_cache.upper() or age or "public" in cache_control or "max-age" in cache_control:
                    vulns.append(
                        {
                            "tipo": "WEB_CACHE_DECEPTION",
                            "path": path,
                            "severidade": "CRITICO",
                            "cache_control": cache_control[:80],
                            "x_cache": x_cache,
                            "age": age,
                            "descricao": "Dynamic content cacheado com extensão estática — WCD!",
                        }
                    )
        except Exception:
            continue
    return vulns


def _test_fat_get(target, page):
    """Testa Fat GET cache poisoning (body in GET request)."""
    try:
        # Verifica baseline - se qualquer dado no body do GET é refletido
        # isso evita FPs onde a aplicação apenas ecoa tudo (ex: debug page)
        baseline_junk = "baseline_fat_get_" + "".join(random.choices(string.ascii_lowercase, k=6))
        baseline_resp = requests.get(
            f"http://{target}{page}",
            data=f"random_field={baseline_junk}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5,
        )
        if baseline_junk in baseline_resp.text:
            return None  # FP: Blind reflection no body do GET

        resp = requests.get(
            f"http://{target}{page}",
            data=f"param={CANARY}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5,
        )
        if CANARY in resp.text:
            return {
                "tipo": "FAT_GET_CACHE_POISON",
                "pagina": page,
                "severidade": "ALTO",
                "descricao": "GET com body é processado — Fat GET cache poisoning possível!",
            }
    except Exception:
        pass
    return None


def _test_parameter_cloaking(target, page):
    """Testa parameter cloaking para cache poisoning."""
    try:
        # Baseline check para ver se qualquer param é refletido
        baseline_junk = "baseline_cloak_" + "".join(random.choices(string.ascii_lowercase, k=6))
        baseline_resp = requests.get(f"http://{target}{page}?cb=1;random={baseline_junk}", timeout=5)
        if baseline_junk in baseline_resp.text:
            return None  # FP: Blind reflection de parametros aninhados

        # Some caches strip query params — inject via fragment/semicolon
        resp = requests.get(f"http://{target}{page}?cb=1;evil={CANARY}", timeout=5)
        if CANARY in resp.text:
            return {
                "tipo": "PARAMETER_CLOAKING",
                "pagina": page,
                "severidade": "ALTO",
                "descricao": "Cache ignorou parâmetro após semicolon — parameter cloaking!",
            }
    except Exception:
        pass
    return None


def _analyze_cache_headers(target, page):
    """Analisa headers de cache para misconfiguration."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}{page}", timeout=5)
        cache_control = resp.headers.get("Cache-Control", "")
        resp.headers.get("Pragma", "")
        vary = resp.headers.get("Vary", "")
        x_cache = resp.headers.get("X-Cache", "")
        cf_cache = resp.headers.get("CF-Cache-Status", "")
        resp.headers.get("Surrogate-Control", "")

        # Public cache without Vary
        if "public" in cache_control and not vary:
            vulns.append(
                {
                    "tipo": "CACHE_PUBLIC_NO_VARY",
                    "pagina": page,
                    "severidade": "MEDIO",
                    "descricao": "Cache-Control: public sem Vary — diferentes user responses cacheadas juntas!",
                }
            )

        # S-maxage (CDN/proxy cache)
        if "s-maxage" in cache_control:
            vulns.append(
                {
                    "tipo": "CACHE_CDN_DETECTED",
                    "pagina": page,
                    "cache_control": cache_control[:80],
                    "severidade": "INFO",
                    "descricao": "CDN/proxy cache detected via s-maxage",
                }
            )

        # CDN detection
        if x_cache or cf_cache:
            vulns.append(
                {
                    "tipo": "CDN_CACHE_DETECTED",
                    "pagina": page,
                    "x_cache": x_cache,
                    "cf_cache": cf_cache,
                    "severidade": "INFO",
                    "descricao": f"CDN cache detected: X-Cache={x_cache}, CF-Cache={cf_cache}",
                }
            )
    except Exception:
        pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Web Cache Poisoning 2026-Grade — Unkeyed Headers, WCD, Fat GET.

    Técnicas: 15 unkeyed headers (XFH/X-Host/XFS/XFP/Port/Prefix/S3-Redirect/RFC7239),
    cache deception (static extension on dynamic paths), Fat GET (body in GET),
    parameter cloaking (semicolon bypass), cache header analysis,
    CDN detection (X-Cache/CF-Cache-Status), s-maxage/Vary analysis.
    Research: James Kettle web cache poisoning, PortSwigger.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for page in PAGES:
        vulns.extend(_test_unkeyed_reflection(target, page))
        vulns.extend(_analyze_cache_headers(target, page))

        fat = _test_fat_get(target, page)
        if fat:
            vulns.append(fat)

        cloak = _test_parameter_cloaking(target, page)
        if cloak:
            vulns.append(cloak)

    # Web Cache Deception
    vulns.extend(_test_cache_deception(target))

    return {
        "plugin": "web_cache_poison",
        "versao": "2026.1",
        "tecnicas": [
            "unkeyed_headers",
            "cache_deception",
            "fat_get",
            "parameter_cloaking",
            "cache_analysis",
            "cdn_detection",
        ],
        "resultados": vulns if vulns else "Nenhum cache poisoning detectado",
    }
