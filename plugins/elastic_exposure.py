# plugins/elastic_exposure.py — Cascavel 2026 Intelligence
import requests
import re


ELASTIC_PORTS = [9200, 9300, 9201, 9202]

ELASTIC_PATHS = {
    "/": ("ES_ROOT", "MEDIO", "Elasticsearch root acessível"),
    "/_cluster/health": ("ES_CLUSTER_HEALTH", "ALTO", "Cluster health exposto"),
    "/_cluster/stats": ("ES_CLUSTER_STATS", "ALTO", "Estatísticas do cluster"),
    "/_cluster/settings": ("ES_CLUSTER_SETTINGS", "CRITICO", "Configurações do cluster"),
    "/_cat/indices?v": ("ES_INDICES", "CRITICO", "Listagem de índices"),
    "/_cat/nodes?v": ("ES_NODES", "ALTO", "Nós do cluster"),
    "/_cat/shards?v": ("ES_SHARDS", "MEDIO", "Shards expostos"),
    "/_cat/allocation?v": ("ES_ALLOCATION", "MEDIO", "Alocação de disco"),
    "/_all/_search?size=10": ("ES_DATA_DUMP", "CRITICO", "Dados de todos os índices"),
    "/_security/_authenticate": ("ES_AUTH_CHECK", "MEDIO", "Endpoint de auth"),
    "/.kibana": ("ES_KIBANA_INDEX", "ALTO", "Índice Kibana"),
    "/_mapping": ("ES_MAPPINGS", "ALTO", "Schema mappings"),
    "/_nodes": ("ES_NODES_INFO", "ALTO", "Informações dos nós"),
    "/_nodes/stats": ("ES_NODES_STATS", "ALTO", "Estatísticas dos nós"),
    "/_snapshot": ("ES_SNAPSHOTS", "CRITICO", "Snapshots/backups acessíveis"),
    "/_aliases": ("ES_ALIASES", "MEDIO", "Aliases expostos"),
    "/_ingest/pipeline": ("ES_PIPELINES", "ALTO", "Ingest pipelines"),
    "/_template": ("ES_TEMPLATES", "MEDIO", "Index templates"),
    "/_tasks": ("ES_TASKS", "MEDIO", "Running tasks"),
}

PII_PATTERNS = ["email", "password", "ssn", "credit_card", "phone",
                "address", "name", "cpf", "rg", "token", "secret"]


def _probe_elastic(target, port):
    """Verifica Elasticsearch endpoints e analisa dados."""
    vulns = []
    for path, (tipo, sev, desc) in ELASTIC_PATHS.items():
        try:
            resp = requests.get(f"http://{target}:{port}{path}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 5:
                vuln = {
                    "tipo": tipo, "porta": port, "path": path,
                    "severidade": sev, "amostra": resp.text[:200],
                    "descricao": f"{desc} em :{port}!",
                }

                # Extract version
                if path == "/":
                    try:
                        data = resp.json()
                        vuln["version"] = data.get("version", {}).get("number", "")
                        vuln["cluster_name"] = data.get("cluster_name", "")
                    except Exception:
                        pass

                # Analyze indices for PII
                if "indices" in path or "search" in path:
                    text_lower = resp.text.lower()
                    pii_found = [p for p in PII_PATTERNS if p in text_lower]
                    if pii_found:
                        vuln["pii_indicators"] = pii_found
                        vuln["severidade"] = "CRITICO"
                        vuln["descricao"] += f" PII detectado: {', '.join(pii_found[:5])}"

                # Check snapshots
                if "snapshot" in path:
                    try:
                        snapshots = resp.json()
                        if snapshots:
                            vuln["descricao"] = "Snapshots de backup acessíveis — exfiltração de dados!"
                    except Exception:
                        pass

                vulns.append(vuln)
        except Exception:
            continue
    return vulns


def _check_kibana(target):
    """Verifica Kibana e OpenSearch Dashboards."""
    vulns = []
    kibana_paths = [
        (5601, "/app/kibana", "KIBANA"),
        (5601, "/app/home", "KIBANA"),
        (5601, "/api/status", "KIBANA_STATUS"),
        (5601, "/api/saved_objects/_find?type=dashboard", "KIBANA_DASHBOARDS"),
        (5601, "/s/default/app/dev_tools", "KIBANA_DEV_TOOLS"),
    ]
    for port, path, label in kibana_paths:
        try:
            resp = requests.get(f"http://{target}:{port}{path}", timeout=5)
            if resp.status_code == 200 and any(k in resp.text.lower()
                                                for k in ["kibana", "opensearch", "elastic"]):
                sev = "CRITICO" if "dev_tools" in path or "saved_objects" in path else "ALTO"
                vulns.append({
                    "tipo": f"{label}_UNAUTH", "porta": port, "path": path,
                    "severidade": sev,
                    "descricao": f"{'Kibana Dev Tools' if 'dev_tools' in path else 'Kibana'} sem auth!",
                })
        except Exception:
            continue
    return vulns


def _check_opensearch(target):
    """Verifica OpenSearch Dashboards (fork do Elasticsearch)."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}:9200/", timeout=5)
        if "opensearch" in resp.text.lower():
            vulns.append({
                "tipo": "OPENSEARCH_DETECTED", "porta": 9200,
                "severidade": "MEDIO",
                "descricao": "OpenSearch detectado (fork AWS do Elasticsearch)",
            })
    except Exception:
        pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Elasticsearch/Kibana/OpenSearch 2026-Grade.

    Técnicas: 19 Elasticsearch paths (cluster/indices/nodes/snapshots/aliases/
    pipelines/templates/tasks), 4 ports (9200-9202/9300), PII detection in data,
    version extraction, Kibana unauth (5 paths incl Dev Tools/saved_objects),
    OpenSearch detection, snapshot/backup exfiltration.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for port in ELASTIC_PORTS:
        vulns.extend(_probe_elastic(target, port))
    vulns.extend(_check_kibana(target))
    vulns.extend(_check_opensearch(target))

    return {
        "plugin": "elastic_exposure", "versao": "2026.1",
        "tecnicas": ["elastic_api", "kibana_unauth", "pii_detection",
                      "opensearch", "snapshot_enum", "version_disclosure"],
        "resultados": vulns if vulns else "Nenhum Elasticsearch exposto",
    }
