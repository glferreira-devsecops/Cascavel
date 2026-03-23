# plugins/ssti_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner SSTI (Server-Side Template Injection).
    Testa Jinja2, Twig, Freemarker, Mako, Velocity, ERB, Smarty.
    """
    import requests

    params = ["name", "template", "msg", "message", "text", "query", "search",
              "input", "content", "title", "greeting"]
    payloads = [
        ("{{7*7}}", "49", "JINJA2/TWIG"),
        ("${7*7}", "49", "FREEMARKER/MAKO"),
        ("#{7*7}", "49", "RUBY_ERB"),
        ("<%= 7*7 %>", "49", "ERB/JSP"),
        ("{{7*'7'}}", "7777777", "JINJA2_CONFIRM"),
        ("#set($x=7*7)${x}", "49", "VELOCITY"),
        ("{php}echo 7*7;{/php}", "49", "SMARTY"),
        ("{{config}}", "SECRET_KEY", "JINJA2_CONFIG_LEAK"),
        ("{{self.__init__.__globals__}}", "os", "JINJA2_RCE_PROBE"),
    ]
    vulns = []

    for param in params:
        for payload, indicator, engine in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6)
                if resp.status_code == 200 and indicator in resp.text:
                    # Confirmar: indicador presente E payload não refletido literalmente
                    # (se o template engine avaliou, o payload bruto não deveria estar exatamente)
                    is_literal_reflection = (resp.text.count(payload) > 0 and resp.text.count(indicator) == resp.text.count(payload))
                    if not is_literal_reflection:
                        vuln = {
                            "tipo": "SSTI",
                            "engine": engine,
                            "parametro": param,
                            "payload": payload,
                            "severidade": "CRITICO",
                        }
                        if "CONFIG_LEAK" in engine:
                            vuln["descricao"] = "Configuração Flask/Jinja2 exposta!"
                        elif "RCE_PROBE" in engine:
                            vuln["descricao"] = "Acesso a globals — possível RCE!"
                        vulns.append(vuln)
                        break
            except Exception:
                continue

    return {"plugin": "ssti_scanner", "resultados": vulns if vulns else "Nenhum SSTI detectado"}
