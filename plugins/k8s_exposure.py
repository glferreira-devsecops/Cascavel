# plugins/k8s_exposure.py — Cascavel 2026 Intelligence
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


K8S_PATHS = {
    "/api": ("K8S_API_ROOT", "ALTO"),
    "/api/v1": ("K8S_API_V1", "ALTO"),
    "/api/v1/namespaces": ("K8S_NAMESPACES", "CRITICO"),
    "/api/v1/pods": ("K8S_PODS", "CRITICO"),
    "/api/v1/secrets": ("K8S_SECRETS", "CRITICO"),
    "/api/v1/configmaps": ("K8S_CONFIGMAPS", "ALTO"),
    "/api/v1/services": ("K8S_SERVICES", "ALTO"),
    "/api/v1/nodes": ("K8S_NODES", "CRITICO"),
    "/api/v1/serviceaccounts": ("K8S_SERVICE_ACCOUNTS", "CRITICO"),
    "/api/v1/persistentvolumes": ("K8S_PVS", "ALTO"),
    "/apis/apps/v1/deployments": ("K8S_DEPLOYMENTS", "ALTO"),
    "/apis/batch/v1/jobs": ("K8S_JOBS", "MEDIO"),
    "/apis/batch/v1/cronjobs": ("K8S_CRONJOBS", "MEDIO"),
    "/apis/networking.k8s.io/v1/ingresses": ("K8S_INGRESSES", "ALTO"),
    "/apis/rbac.authorization.k8s.io/v1/clusterroles": ("K8S_RBAC", "CRITICO"),
    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": ("K8S_RBAC_BINDINGS", "CRITICO"),
    "/healthz": ("K8S_HEALTHZ", "BAIXO"),
    "/livez": ("K8S_LIVEZ", "BAIXO"),
    "/readyz": ("K8S_READYZ", "BAIXO"),
    "/metrics": ("K8S_METRICS", "MEDIO"),
    "/version": ("K8S_VERSION", "BAIXO"),
    "/openapi/v2": ("K8S_OPENAPI", "MEDIO"),
    "/apis": ("K8S_APIS", "MEDIO"),
}

K8S_PORTS = [6443, 8443, 10250, 10255, 8080, 443, 8001, 31337]

DASHBOARD_PATHS = [
    "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
    "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
    "/dashboard/",
]

ETCD_PORTS = [2379, 2380]


def _probe_k8s_api(target, port):
    """Testa endpoints da API Kubernetes."""
    vulns = []
    scheme = "https" if port in (6443, 8443, 443) else "http"
    for path, (tipo, sev) in K8S_PATHS.items():
        url = f"{scheme}://{target}:{port}{path}"
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                vuln = {
                    "tipo": tipo,
                    "porta": port,
                    "path": path,
                    "severidade": sev,
                    "amostra": resp.text[:200],
                    "descricao": f"K8s API {path} acessível sem auth em :{port}!",
                }
                # Extract version info
                if path == "/version":
                    try:
                        ver = resp.json()
                        vuln["k8s_version"] = ver.get("gitVersion", "")
                    except Exception:
                        pass
                # Count resources
                if path in ("/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces"):
                    try:
                        items = resp.json().get("items", [])
                        vuln["resource_count"] = len(items)
                    except Exception:
                        pass
                vulns.append(vuln)
            elif resp.status_code == 403:
                vulns.append(
                    {
                        "tipo": f"{tipo}_FORBIDDEN",
                        "porta": port,
                        "path": path,
                        "severidade": "BAIXO",
                        "descricao": f"K8s API {path} existe mas retorna 403 — auth bypass possível!",
                    }
                )
        except Exception:
            continue
    return vulns


def _check_kubelet(target):
    """Verifica Kubelet API exposta (10250/10255)."""
    vulns = []
    kubelet_paths = {
        "/pods": "KUBELET_PODS",
        "/runningpods/": "KUBELET_RUNNING",
        "/metrics": "KUBELET_METRICS",
        "/stats/summary": "KUBELET_STATS",
        "/spec/": "KUBELET_SPEC",
        "/healthz": "KUBELET_HEALTH",
    }
    for port in [10250, 10255]:
        scheme = "https" if port == 10250 else "http"
        for path, tipo in kubelet_paths.items():
            try:
                resp = requests.get(f"{scheme}://{target}:{port}{path}", timeout=5, verify=False)
                if resp.status_code == 200 and len(resp.text) > 10:
                    sev = "CRITICO" if path in ("/pods", "/runningpods/", "/stats/summary") else "ALTO"
                    vulns.append(
                        {
                            "tipo": tipo,
                            "porta": port,
                            "path": path,
                            "severidade": sev,
                            "descricao": f"Kubelet {path} exposto em :{port} — RCE em pods possível!",
                        }
                    )
            except Exception:
                continue
    return vulns


def _check_dashboard(target):
    """Verifica Kubernetes Dashboard sem auth."""
    vulns = []
    for port in [443, 8443, 8001, 30000]:
        for path in DASHBOARD_PATHS:
            try:
                resp = requests.get(f"https://{target}:{port}{path}", timeout=5, verify=False)
                if resp.status_code == 200 and any(k in resp.text.lower() for k in ["dashboard", "kubernetes"]):
                    vulns.append(
                        {
                            "tipo": "K8S_DASHBOARD_UNAUTH",
                            "porta": port,
                            "severidade": "CRITICO",
                            "descricao": "Kubernetes Dashboard sem auth — cluster takeover!",
                        }
                    )
            except Exception:
                continue
    return vulns


def _check_etcd(target):
    """Verifica etcd exposto — contém todos os secrets K8s."""
    vulns = []
    for port in ETCD_PORTS:
        try:
            resp = requests.get(f"http://{target}:{port}/v2/keys/", timeout=5)
            if resp.status_code == 200 and "node" in resp.text:
                vulns.append(
                    {
                        "tipo": "ETCD_EXPOSED",
                        "porta": port,
                        "severidade": "CRITICO",
                        "descricao": "etcd exposto sem auth — todos os secrets K8s acessíveis!",
                    }
                )
        except Exception:
            pass
        # v3 API
        try:
            resp = requests.post(
                f"http://{target}:{port}/v3/kv/range",
                json={"key": "AA=="},  # empty key
                timeout=5,
            )
            if resp.status_code == 200:
                vulns.append(
                    {
                        "tipo": "ETCD_V3_EXPOSED",
                        "porta": port,
                        "severidade": "CRITICO",
                        "descricao": "etcd v3 API exposta — key-value dump possível!",
                    }
                )
        except Exception:
            pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Kubernetes Exposure 2026-Grade — API, Kubelet, Dashboard, etcd.

    Técnicas: 23 K8s API paths (RBAC/serviceaccounts/ingresses/cronjobs),
    8 API ports, 6 Kubelet paths (pods/stats/spec), Dashboard detection (4 ports),
    etcd v2/v3 exposure, version disclosure, resource counting,
    403-to-bypass detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for port in K8S_PORTS:
        vulns.extend(_probe_k8s_api(target, port))
    vulns.extend(_check_kubelet(target))
    vulns.extend(_check_dashboard(target))
    vulns.extend(_check_etcd(target))

    return {
        "plugin": "k8s_exposure",
        "versao": "2026.1",
        "tecnicas": ["k8s_api", "kubelet", "dashboard", "etcd", "rbac_enum", "version_disclosure"],
        "resultados": vulns if vulns else "Nenhuma exposição K8s detectada",
    }
