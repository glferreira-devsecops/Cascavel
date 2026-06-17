# plugins/airflow_jwt_config_cve.py
import requests


def run(target, ip, open_ports, banners, context=None):
    """
    Detector do CVE-2026-41017 (Apache Airflow JWTRefreshMiddleware).
    Airflow geralmente roda na porta 8080.
    """
    _ = (ip, banners)

    if 8080 not in open_ports and 80 not in open_ports and 443 not in open_ports:
        return {
            "plugin": "airflow_jwt_config_cve",
            "resultados": "Portas Web não detectadas",
        }

    portas_alvo = [p for p in open_ports if p in (80, 443, 8080)]
    resultados = []

    for porta in portas_alvo:
        protocolo = "http" if porta in (80, 8080) else "https"
        url = f"{protocolo}://{target}:{porta}/login/"

        try:
            resp = requests.get(url, timeout=5, verify=False)  # nosec B501

            if "Airflow" in resp.text or "Apache Airflow" in resp.headers.get("Server", ""):
                resultados.append(
                    {
                        "porta": porta,
                        "status": "Apache Airflow Detectado",
                        "aviso": "Apache Airflow Web UI exposto. Verifique a mitigação para o bypass de JWT Refresh (CVE-2026-41017).",
                    }
                )
        except requests.exceptions.RequestException:
            pass

    if not resultados:
        return {
            "plugin": "airflow_jwt_config_cve",
            "resultados": "Nenhum Airflow UI vulnerável detectado.",
        }

    return {"plugin": "airflow_jwt_config_cve", "resultados": resultados}
