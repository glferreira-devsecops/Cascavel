# plugins/cloud_metadata.py
def run(target, ip, open_ports, banners):
    """
    Scanner de Cloud Metadata Exposure.
    Detecta endpoints de metadata de cloud expostos publicamente.
    Cobre AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Oracle Cloud.
    Tendência 2026: IMDSv2 bypass e token harvesting.
    """
    import requests

    metadata_endpoints = [
        # AWS IMDSv1
        {"url": "http://{ip}/latest/meta-data/", "provider": "AWS", "version": "IMDSv1"},
        {"url": "http://{ip}/latest/meta-data/iam/security-credentials/", "provider": "AWS", "version": "IAM_CREDS"},
        {"url": "http://{ip}/latest/user-data/", "provider": "AWS", "version": "USER_DATA"},
        # GCP
        {"url": "http://{ip}/computeMetadata/v1/project/project-id", "provider": "GCP",
         "headers": {"Metadata-Flavor": "Google"}, "version": "v1"},
        {"url": "http://{ip}/computeMetadata/v1/instance/service-accounts/default/token", "provider": "GCP",
         "headers": {"Metadata-Flavor": "Google"}, "version": "TOKEN"},
        # Azure
        {"url": "http://{ip}/metadata/instance?api-version=2021-02-01", "provider": "Azure",
         "headers": {"Metadata": "true"}, "version": "IMDS"},
        # DigitalOcean
        {"url": "http://{ip}/metadata/v1.json", "provider": "DigitalOcean", "version": "v1"},
        # Oracle Cloud
        {"url": "http://{ip}/opc/v2/instance/", "provider": "OracleCloud",
         "headers": {"Authorization": "Bearer Oracle"}, "version": "v2"},
    ]

    vulns = []
    info = []

    for ep in metadata_endpoints:
        url = ep["url"].replace("{ip}", ip)
        headers = ep.get("headers", {})
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 10:
                # Análise de conteúdo
                entry = {
                    "provider": ep["provider"],
                    "version": ep["version"],
                    "status": resp.status_code,
                    "tamanho": len(resp.text),
                }

                # Detectar dados sensíveis
                sensivel = False
                keywords = ["AccessKeyId", "SecretAccessKey", "Token",
                            "password", "private_key", "credentials",
                            "access_token", "client_secret"]
                for kw in keywords:
                    if kw.lower() in resp.text.lower():
                        sensivel = True
                        entry["dados_sensiveis"] = True
                        entry["amostra"] = resp.text[:300]
                        break

                if sensivel:
                    entry["severidade"] = "CRITICO"
                    entry["tipo"] = "CREDENTIAL_LEAK"
                    vulns.append(entry)
                else:
                    entry["severidade"] = "ALTO"
                    entry["tipo"] = "METADATA_EXPOSED"
                    entry["amostra"] = resp.text[:200]
                    vulns.append(entry)

        except Exception:
            continue

    return {"plugin": "cloud_metadata", "resultados": vulns if vulns else "Nenhum metadata endpoint exposto"}
