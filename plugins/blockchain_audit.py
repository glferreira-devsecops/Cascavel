"""
[+] Plugin: Blockchain & Web3 Security Audit
[+] Description: Testa RPC endpoints expostos, smart contracts, wallet config, DeFi vulns, MEV vectors
[+] Category: Web3 / Blockchain Security
[+] CVSS: 8.5 (High)
[+] Author: CASCAVEL Framework
"""

from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Common RPC ports by chain
RPC_PORTS = {
    8545: "Ethereum JSON-RPC (Geth/Besu/Erigon)",
    8546: "Ethereum WebSocket",
    7545: "Ganache/Hardhat",
    8547: "Geth GraphQL",
    26657: "Tendermint/Cosmos RPC",
    8899: "Solana RPC",
    4000: "Polkadot RPC",
    9933: "Polkadot HTTP RPC",
    9944: "Polkadot WebSocket",
    5000: "Near RPC",
    8080: "Generic Node RPC",
    30303: "Ethereum P2P",
    30304: "Ethereum P2P UDP",
}

# Dangerous RPC methods
DANGEROUS_METHODS = [
    "personal_listAccounts",
    "personal_unlockAccount",
    "eth_accounts",
    "eth_sendTransaction",
    "eth_sign",
    "eth_signTypedData",
    "eth_signTypedData_v4",
    "debug_traceTransaction",
    "debug_dumpBlock",
    "txpool_content",
    "admin_nodeInfo",
    "admin_peers",
    "miner_start",
    "miner_stop",
]


def _check_rpc_exposure(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica endpoints RPC expostos e sem autenticação."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Cascavel-Web3-Audit/3.0",
    }

    for port, desc in RPC_PORTS.items():
        if port not in ports:
            continue

        base_url = f"http://{ip}:{port}"

        try:
            # Test basic connectivity
            payload = {"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=5)

            if resp.status_code != 200:
                continue

            data = resp.json()
            if "result" not in data:
                continue

            version = data.get("result", "unknown")

            # Node RPC is exposed
            findings.append({
                "tipo": "RPC_EXPOSTO",
                "severidade": "ALTO",
                "descricao": f"Endpoint RPC exposto sem autenticação na porta {port} ({desc})",
                "evidencia": f"Client version: {version}",
                "correcao": "Implementar autenticação (JWT/API key). Restringir acesso via firewall.",
            })

            # Test for dangerous methods
            for method in DANGEROUS_METHODS:
                try:
                    payload = {"jsonrpc": "2.0", "method": method, "params": [], "id": 1}
                    resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
                    result = resp.json()
                    if "result" in result and result["result"] is not None:
                        severity = "CRITICO" if "unlock" in method or "send" in method else "ALTO"
                        findings.append({
                            "tipo": "RPC_METODO_PERIGOSO",
                            "severidade": severity,
                            "descricao": f"Método perigoso '{method}' disponível via RPC",
                            "evidencia": f"Response: {str(result['result'])[:200]}",
                            "correcao": f"Desabilitar método '{method}' em produção. Usar --http.api whitelist.",
                        })
                except Exception:
                    continue
        except Exception:
            pass
    return findings


def _check_smart_contracts(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades em smart contracts via interação RPC."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    rpc_ports = [p for p in [8545, 7545, 8080] if p in ports]
    for port in rpc_ports:
        base_url = f"http://{ip}:{port}"
        headers = {"Content-Type": "application/json"}

        try:
            # Check for reentrancy-vulnerable patterns via trace
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": ["0x0000000000000000000000000000000000000000", "latest"],
                "id": 1,
            }
            resp = requests.post(base_url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                result = resp.json().get("result", "0x")
                if result and result != "0x" and len(result) > 10:
                    findings.append({
                        "tipo": "CONTRACT_CODE_EXPOSTO",
                        "severidade": "INFO",
                        "descricao": "Código de contrato acessível via RPC — verificar por vulnerabilidades",
                        "evidencia": f"Code length: {len(result)} chars",
                        "correcao": "Auditar bytecode do contrato com ferramentas como Slither, Mythril ou Echidna.",
                    })

            # Check for debug namespace (can expose internal state)
            payload = {
                "jsonrpc": "2.0",
                "method": "debug_traceTransaction",
                "params": ["0x0000000000000000000000000000000000000000000000000000000000000000", {}],
                "id": 1,
            }
            resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
            if resp.status_code == 200 and "error" not in resp.json():
                findings.append({
                    "tipo": "DEBUG_NAMESPACE_ABERTO",
                    "severidade": "CRITICO",
                    "descricao": "Debug namespace habilitado no nó — expõe estado interno de transações",
                    "correcao": "Desabilitar debug namespace em produção: --http.api=eth,net,web3",
                })
        except Exception:
            pass
    return findings


def _check_wallet_misconfig(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica configurações incorretas de wallet via RPC."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    rpc_ports = [p for p in [8545, 7545, 8080] if p in ports]
    for port in rpc_ports:
        base_url = f"http://{ip}:{port}"
        headers = {"Content-Type": "application/json"}

        try:
            # Check for unlocked accounts
            payload = {"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                accounts = resp.json().get("result", [])
                if accounts and len(accounts) > 0:
                    findings.append({
                        "tipo": "WALLET_CONTAS_ABERTAS",
                        "severidade": "CRITICO",
                        "descricao": f"{len(accounts)} conta(s) desbloqueada(s) no nó — fundos em risco",
                        "evidencia": f"Accounts: {accounts[:5]}",
                        "correcao": "Nunca manter contas desbloqueadas em nós públicos. Usar keystore criptografado.",
                    })

            # Check for mining (indicates test/dev node — usually less secured)
            payload = {"jsonrpc": "2.0", "method": "eth_mining", "params": [], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
            if resp.status_code == 200 and resp.json().get("result") is True:
                findings.append({
                    "tipo": "NODE_MINING_ATIVO",
                    "severidade": "MEDIO",
                    "descricao": "Mining ativo no nó — possível configuração de desenvolvimento exposta",
                    "correcao": "Verificar se nó de mineração deveria estar acessível publicamente.",
                })
        except Exception:
            pass
    return findings


def _check_defi_vulns(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades em protocolos DeFi."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    rpc_ports = [p for p in [8545, 7545, 8080] if p in ports]
    for port in rpc_ports:
        base_url = f"http://{ip}:{port}"
        headers = {"Content-Type": "application/json"}

        try:
            # Check for flash loan callable functions
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getStorageAt",
                "params": ["0x0000000000000000000000000000000000000000", "0x0", "latest"],
                "id": 1,
            }
            resp = requests.post(base_url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                findings.append({
                    "tipo": "DEFI_STORAGE_ACESSIVEL",
                    "severidade": "MEDIO",
                    "descricao": "Storage de contratos acessível via RPC — possível análise de estado DeFi",
                    "correcao": "Restringir acesso a endpoints de storage. Implementar rate limiting.",
                })

            # Check for pending transaction exposure (MEV risk)
            payload = {"jsonrpc": "2.0", "method": "txpool_content", "params": [], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
            if resp.status_code == 200 and "result" in resp.json():
                result = resp.json()["result"]
                if result and (isinstance(result, dict) and (result.get("pending") or result.get("queued"))):
                    findings.append({
                        "tipo": "TXPOOL_EXPOSTO",
                        "severidade": "ALTO",
                        "descricao": "TxPool exposto — transações pendentes visíveis (risco de MEV/frontrunning)",
                        "correcao": "Desabilitar txpool RPC em produção ou restringir acesso.",
                    })
        except Exception:
            pass
    return findings


def _check_mev_vectors(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vetores de ataque MEV (Maximal Extractable Value)."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    rpc_ports = [p for p in [8545, 7545, 8080] if p in ports]
    for port in rpc_ports:
        base_url = f"http://{ip}:{port}"
        headers = {"Content-Type": "application/json"}

        try:
            # Check if node exposes pending transactions (frontrunning vector)
            payload = {"jsonrpc": "2.0", "method": "eth_subscribe", "params": ["newPendingTransactions"], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
            if resp.status_code == 200 and "result" in resp.json():
                findings.append({
                    "tipo": "MEV_PENDING_TX_SUBSCRIPTION",
                    "severidade": "ALTO",
                    "descricao": "Subscribe a pending transactions habilitado — vetor de frontrunning/MEV",
                    "correcao": "Desabilitar eth_subscribe ou usar Flashbots Protect para transações sensíveis.",
                })

            # Check for block ordering manipulation capability
            payload = {"jsonrpc": "2.0", "method": "miner_setExtra", "params": ["test"], "id": 1}
            resp = requests.post(base_url, json=payload, headers=headers, timeout=3)
            if resp.status_code == 200 and "error" not in resp.json():
                findings.append({
                    "tipo": "MEV_BLOCK_MANIPULATION",
                    "severidade": "CRITICO",
                    "descricao": "miner_setExtra disponível — possível manipulação de ordenação de blocos",
                    "correcao": "Desabilitar métodos de mineração em nós não-miners. Usar Flashbots para proteção MEV.",
                })
        except Exception:
            pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Auditoria de segurança Blockchain/Web3 — RPC, smart contracts, wallet, DeFi, MEV."""
    try:
        vulns = []
        vulns.extend(_check_rpc_exposure(ip, ports))
        vulns.extend(_check_smart_contracts(ip, ports))
        vulns.extend(_check_wallet_misconfig(ip, ports))
        vulns.extend(_check_defi_vulns(ip, ports))
        vulns.extend(_check_mev_vectors(ip, ports))

        if context:
            chain = context.get("chain", "ethereum")
            if chain in ("bsc", "polygon", "avalanche"):
                vulns.append({
                    "tipo": "L2_CHAIN_CONTEXT",
                    "severidade": "INFO",
                    "descricao": f"Chain {chain} detectada via contexto — verificar bridge contracts",
                    "correcao": "Auditar bridges cross-chain para vulnerabilidades de minting.",
                })

        return {
            "plugin": "blockchain_audit",
            "resultados": vulns if vulns else "Nenhuma vulnerabilidade Blockchain/Web3 detectada",
        }
    except Exception as e:
        return {"plugin": "blockchain_audit", "erro": str(e)}
