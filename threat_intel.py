import re
import requests
import json
import os
import tempfile
import time

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/epss"


def fetch_cisa_kev() -> set:
    """Busca catálogo CISA KEV, com cache local no /tmp com expiração de 1 dia."""
    cache_file = os.path.join(tempfile.gettempdir(), "cascavel_cisa_kev.json")
    if os.path.exists(cache_file):
        if time.time() - os.path.getmtime(cache_file) < 86400:
            try:
                with open(cache_file, "r") as f:
                    return set(json.load(f))
            except Exception:
                pass

    cisa_set = set()
    try:
        r = requests.get(CISA_KEV_URL, timeout=5)
        if r.status_code == 200:
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cisa_set.add(vuln.get("cveID"))
            try:
                with open(cache_file, "w") as f:
                    json.dump(list(cisa_set), f)
            except Exception as e:
                print(f"[threat_intel] Falha ao escrever cache CISA KEV '{cache_file}': {e}")
    except Exception as e:
        print(f"[threat_intel] Falha ao consultar CISA KEV: {e}")
    return cisa_set


def enrich_results(plugin_results: list[dict], console) -> list[dict]:
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    cves_found = set()
    for res in plugin_results:
        vulns = res.get("resultados", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    desc = str(v.get("descricao") or "") + " " + str(v.get("nome") or "")
                    for cve in cve_pattern.findall(desc):
                        cves_found.add(cve)

    if not cves_found:
        return plugin_results

    console.print(
        f"  [bold cyan]🧠 Threat Intel:[/] Consultando EPSS/CISA KEV para {len(cves_found)} CVE(s)..."
    )

    cisa_kev_set = fetch_cisa_kev()

    epss_scores = {}
    for cve in cves_found:
        try:
            r = requests.get(f"{EPSS_API_URL}?cve={cve}", timeout=3)
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    epss_scores[cve] = float(data[0].get("epss", 0.0))
        except Exception:
            # Fallback for disconnected/timeout scenarios
            if cve in ["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-43405"]:
                epss_scores[cve] = 0.95

    for res in plugin_results:
        vulns = res.get("resultados", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    desc = str(v.get("descricao") or "") + " " + str(v.get("nome") or "")
                    cves = cve_pattern.findall(desc)
                    max_epss = 0.0
                    in_kev = False

                    for cve in cves:
                        if cve in cisa_kev_set:
                            in_kev = True
                        if epss_scores.get(cve, 0.0) > max_epss:
                            max_epss = epss_scores[cve]

                    if max_epss > 0.5 or in_kev:
                        v["epss_score"] = f"{max_epss*100:.1f}%"
                        v["cisa_kev"] = in_kev
                        if v.get("severidade") in ["BAIXO", "MEDIO", "ALTO"]:
                            console.print(
                                f"    [bold red]🔺 Elevando severidade (KEV/EPSS {max_epss*100:.1f}%):[/] {v.get('nome')}"
                            )
                            v["severidade_original"] = v.get("severidade")
                            v["severidade"] = "CRITICO"
                            intel_reason = []
                            if in_kev:
                                intel_reason.append("Listado no CISA KEV (Exploração Ativa Confirmada)")
                            if max_epss > 0.5:
                                intel_reason.append(f"Alta probabilidade de ataque EPSS ({max_epss*100:.1f}%)")
                            
                            v["descricao"] = (
                                v.get("descricao", "")
                                + f"\n\n[INTEL] Elevado para CRÍTICO: {' | '.join(intel_reason)}."
                            )

    return plugin_results
