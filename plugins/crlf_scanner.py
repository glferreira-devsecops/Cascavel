# plugins/crlf_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner CRLF Injection (HTTP Response Splitting).
    Testa injeção de headers via CRLF em parâmetros GET.
    Detecta: HTTP Response Splitting, XSS via CRLF, Cache Poisoning.
    """
    import requests

    params = ["url", "redirect", "next", "return", "path", "page", "lang", "ref", "goto"]
    payloads = [
        "%0d%0aInjected-Header:CascavelTest",
        "%0d%0a%0d%0a<html>CRLFTest</html>",
        "%0d%0aSet-Cookie:crlftest=true",
        "%0D%0AX-Custom:CascavelCRLF",
        "\r\nInjected-Header:CascavelTest",
        "%E5%98%8A%E5%98%8DInjected:UnicodeCRLF",  # Unicode bypass
    ]
    vulns = []

    for param in params:
        for payload in payloads:
            url = f"http://{target}/?{param}={payload}"
            try:
                resp = requests.get(url, timeout=6, allow_redirects=False)

                # Verificar se o header injetado aparece na resposta
                for header_nome, header_valor in resp.headers.items():
                    header_lower = header_nome.lower()
                    if "injected" in header_lower or "cascavel" in header_valor.lower():
                        vuln = {
                            "tipo": "CRLF_INJECTION",
                            "parametro": param,
                            "payload": payload,
                            "header_injetado": f"{header_nome}: {header_valor}",
                            "severidade": "ALTO",
                        }
                        # Classificar tipo
                        if "set-cookie" in payload.lower():
                            vuln["subtipo"] = "SESSION_FIXATION"
                            vuln["severidade"] = "CRITICO"
                        elif "<html>" in payload:
                            vuln["subtipo"] = "RESPONSE_SPLITTING"
                            vuln["severidade"] = "CRITICO"
                        vulns.append(vuln)
                        break

                # Verificar body split
                if "<html>CRLFTest</html>" in resp.text and "CRLFTest" not in url.replace(payload, ""):
                    vulns.append({
                        "tipo": "HTTP_RESPONSE_SPLITTING",
                        "parametro": param,
                        "payload": payload,
                        "severidade": "CRITICO",
                        "descricao": "Body injetado via CRLF — full response splitting"
                    })
            except Exception:
                continue

    return {
        "plugin": "crlf_scanner",
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade CRLF detectada"
    }
