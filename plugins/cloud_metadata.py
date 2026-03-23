# plugins/cloud_metadata.py
def run(target, ip, open_ports, banners):
    """
    Scanner Cloud Metadata Exposure.
    2026 Intel: IMDSv2 compliance check, GCP service account tokens,
    Azure Managed Identity, Oracle Cloud IMDS, DigitalOcean, Alibaba,
    Kubernetes Service Account, Container metadata.
    Refs: hackingthe.cloud/2026, LexisNexis breach (Feb 2026).
    """
    import requests
    import time

    resultado = {"providers_detectados": [], "vulns": [], "metadados": {}}

    # AWS IMDSv1
    aws_paths = [
        ("/latest/meta-data/instance-id", "INSTANCE_ID"),
        ("/latest/meta-data/local-ipv4", "LOCAL_IP"),
        ("/latest/meta-data/ami-id", "AMI_ID"),
        ("/latest/meta-data/hostname", "HOSTNAME"),
        ("/latest/meta-data/iam/security-credentials/", "IAM_ROLES"),
        ("/latest/user-data/", "USER_DATA"),
        ("/latest/dynamic/instance-identity/document", "IDENTITY_DOC"),
    ]
    for path, label in aws_paths:
        try:
            resp = requests.get(f"http://169.254.169.254{path}", timeout=3)
            if resp.status_code == 200 and len(resp.text) > 2:
                resultado["metadados"][f"aws_{label}"] = resp.text[:200]
                if label == "IAM_ROLES":
                    role_name = resp.text.strip().split("\n")[0]
                    try:
                        creds = requests.get(
                            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                            timeout=3)
                        if "AccessKeyId" in creds.text:
                            resultado["vulns"].append({
                                "tipo": "AWS_CREDENTIALS_EXPOSED",
                                "role": role_name, "severidade": "CRITICO",
                                "descricao": "AWS IAM credentials via IMDSv1! (LexisNexis-style breach)"
                            })
                    except Exception:
                        pass
                if not any(p["provider"] == "AWS" for p in resultado["providers_detectados"]):
                    resultado["providers_detectados"].append({"provider": "AWS", "imds_version": "v1"})
        except Exception:
            continue

    # AWS IMDSv2 check (token required)
    try:
        token_resp = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=3)
        if token_resp.status_code == 200:
            token = token_resp.text
            v2_resp = requests.get(
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token}, timeout=3)
            if v2_resp.status_code == 200:
                resultado["providers_detectados"].append({"provider": "AWS", "imds_version": "v2"})
                resultado["vulns"].append({
                    "tipo": "AWS_IMDSv2_ATIVO", "severidade": "INFO",
                    "descricao": "IMDSv2 ativo — proteção contra SSRF simples"
                })
    except Exception:
        pass

    # GCP
    gcp_paths = [
        ("/computeMetadata/v1/project/project-id", "PROJECT_ID"),
        ("/computeMetadata/v1/instance/hostname", "HOSTNAME"),
        ("/computeMetadata/v1/instance/zone", "ZONE"),
        ("/computeMetadata/v1/instance/service-accounts/default/email", "SA_EMAIL"),
        ("/computeMetadata/v1/instance/service-accounts/default/token", "SA_TOKEN"),
        ("/computeMetadata/v1/instance/attributes/ssh-keys", "SSH_KEYS"),
    ]
    for path, label in gcp_paths:
        try:
            resp = requests.get(f"http://metadata.google.internal{path}",
                                headers={"Metadata-Flavor": "Google"}, timeout=3)
            if resp.status_code == 200:
                resultado["metadados"][f"gcp_{label}"] = resp.text[:200]
                if label == "SA_TOKEN":
                    resultado["vulns"].append({
                        "tipo": "GCP_TOKEN_EXPOSED", "severidade": "CRITICO",
                        "descricao": "GCP Service Account OAuth token exposto!"
                    })
                elif label == "SSH_KEYS":
                    resultado["vulns"].append({
                        "tipo": "GCP_SSH_KEYS_EXPOSED", "severidade": "CRITICO",
                        "descricao": "SSH keys expostas via metadata — privilege escalation!"
                    })
                if not any(p["provider"] == "GCP" for p in resultado["providers_detectados"]):
                    resultado["providers_detectados"].append({"provider": "GCP"})
        except Exception:
            continue

    # Azure IMDS + Managed Identity
    azure_paths = [
        ("/metadata/instance?api-version=2021-02-01", "INSTANCE"),
        ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "MANAGED_ID_TOKEN"),
    ]
    for path, label in azure_paths:
        try:
            resp = requests.get(f"http://169.254.169.254{path}",
                                headers={"Metadata": "true"}, timeout=3)
            if resp.status_code == 200:
                resultado["metadados"][f"azure_{label}"] = resp.text[:200]
                if label == "MANAGED_ID_TOKEN" and "access_token" in resp.text:
                    resultado["vulns"].append({
                        "tipo": "AZURE_MANAGED_IDENTITY_TOKEN", "severidade": "CRITICO",
                        "descricao": "Azure AD token via Managed Identity — full cloud compromise!"
                    })
                if not any(p["provider"] == "AZURE" for p in resultado["providers_detectados"]):
                    resultado["providers_detectados"].append({"provider": "AZURE"})
        except Exception:
            continue

    # DigitalOcean
    try:
        resp = requests.get("http://169.254.169.254/metadata/v1.json", timeout=3)
        if resp.status_code == 200 and "droplet_id" in resp.text:
            resultado["providers_detectados"].append({"provider": "DIGITALOCEAN"})
            resultado["metadados"]["do"] = resp.text[:200]
    except Exception:
        pass

    # Alibaba Cloud
    try:
        resp = requests.get("http://100.100.100.200/latest/meta-data/instance-id", timeout=3)
        if resp.status_code == 200 and len(resp.text) > 5:
            resultado["providers_detectados"].append({"provider": "ALIBABA"})
    except Exception:
        pass

    # Oracle Cloud
    try:
        resp = requests.get("http://169.254.169.254/opc/v2/instance/",
                            headers={"Authorization": "Bearer Oracle"}, timeout=3)
        if resp.status_code == 200:
            resultado["providers_detectados"].append({"provider": "ORACLE"})
    except Exception:
        pass

    # Kubernetes Service Account
    try:
        resp = requests.get("https://kubernetes.default.svc/api/v1/namespaces", timeout=3, verify=False)
        if resp.status_code in [200, 403] and "namespaces" in resp.text.lower():
            resultado["vulns"].append({
                "tipo": "K8S_API_ACCESSIBLE", "severidade": "ALTO",
                "descricao": "Kubernetes API server acessível!"
            })
    except Exception:
        pass

    return {"plugin": "cloud_metadata", "resultados": resultado}
