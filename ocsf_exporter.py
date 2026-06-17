import json
import os
import datetime


def export_ocsf(
    target: str, ip: str, plugin_results: list[dict], elapsed: float, output_dir: str
) -> str:
    """Exporta resultados no formato Open Cybersecurity Schema Framework (OCSF v1.1.0)"""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    filename = os.path.join(
        output_dir,
        f"cascavel_ocsf_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )

    events = []

    for res in plugin_results:
        plugin_name = res.get("plugin", "unknown")
        vulns = res.get("resultados", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    sev_str = str(v.get("severidade", "Info")).lower()
                    severity_id = 1  # Info
                    if sev_str == "critico":
                        severity_id = 6
                    elif sev_str == "alto":
                        severity_id = 5
                    elif sev_str == "medio":
                        severity_id = 3
                    elif sev_str == "baixo":
                        severity_id = 2

                    vuln_dict = {
                        "title": v.get("nome", plugin_name),
                        "desc": v.get("descricao", ""),
                        "remediation": {
                            "desc": v.get("correcao", "No remediation provided")
                        },
                    }
                    event = {
                        "category_name": "Findings",
                        "category_uid": 2,
                        "class_name": "Vulnerability Finding",
                        "class_uid": 2002,
                        "activity_id": 1,
                        "activity_name": "Create",
                        "severity_id": severity_id,
                        "severity": sev_str.capitalize(),
                        "time": ts,
                        "message": v.get(
                            "descricao", v.get("nome", "Vulnerability detected")
                        ),
                        "vulnerability": vuln_dict,
                        "observables": [
                            {"name": "hostname", "type_id": 1, "value": target},
                            {"name": "ip_address", "type_id": 2, "value": ip},
                        ],
                    }
                    if "epss_score" in v:
                        vuln_dict["epss_score"] = v["epss_score"]
                    events.append(event)

    with open(filename, "w", encoding="utf-8") as f:
        # OCSF is often exported as JSON Lines (NDJSON)
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    return filename
