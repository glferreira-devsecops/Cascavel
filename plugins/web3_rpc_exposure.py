"""
[+] Plugin: Web3 RPC Exposure (Blockchain/Web3)
[+] Description: Descobre e explora JSON-RPC de Nodes Ethereum sem autenticação
[+] Category: Infrastructure Exposure
[+] CVSS: 9.8 (Critical)
[+] Author: CASCAVEL Framework
"""

import requests


def run(target, ip, ports, banners):
    finding = None
    # Portas comuns de RPC (Geth, Besu, Erigon, Hardhat)
    web3_ports = [8545, 8546, 7545]

    headers = {"Content-Type": "application/json", "User-Agent": "Cascavel-Web3-Probe/3.0.1"}

    payload = {"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 1}

    for port in web3_ports:
        if port not in ports:
            # Em alguns modos o framework tenta em todas as portas listadas
            continue

        base_url = f"http://{ip}:{port}"
        try:
            resp = requests.post(base_url, json=payload, headers=headers, timeout=5)

            if resp.status_code == 200 and "result" in resp.json():
                accounts = resp.json().get("result", [])

                finding = {
                    "vulnerability": "Web3 JSON-RPC Unauthenticated Exposure",
                    "severity": "CRITICAL",
                    "description": "Nó Web3 (Ethereum/EVM) expondo a interface JSON-RPC na rede sem autenticação. Permite chamadas de contrato e manipulação de estado.",
                    "endpoint": f"http://{ip}:{port}",
                    "payload": "eth_accounts",
                    "evidence": f"Accounts found: {accounts[:3]}..."
                    if accounts
                    else "RPC Active, no accounts unlocked.",
                }
                break
        except Exception:
            pass

    return finding
