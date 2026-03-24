# plugins/cloud_metadata.py — Cascavel 2026 Intelligence
import requests
import time


AWS_PATHS = [
    ("/latest/meta-data/instance-id", "INSTANCE_ID"),
    ("/latest/meta-data/local-ipv4", "LOCAL_IP"),
    ("/latest/meta-data/public-ipv4", "PUBLIC_IP"),
    ("/latest/meta-data/ami-id", "AMI_ID"),
    ("/latest/meta-data/hostname", "HOSTNAME"),
    ("/latest/meta-data/iam/security-credentials/", "IAM_ROLES"),
    ("/latest/meta-data/iam/info", "IAM_INFO"),
    ("/latest/user-data/", "USER_DATA"),
    ("/latest/dynamic/instance-identity/document", "IDENTITY_DOC"),
    ("/latest/meta-data/placement/availability-zone", "AZ"),
    ("/latest/meta-data/network/interfaces/macs/", "NETWORK_MACS"),
    ("/latest/meta-data/public-keys/", "SSH_KEYS"),
    ("/latest/meta-data/services/domain", "AWS_DOMAIN"),
    ("/latest/meta-data/security-groups", "SECURITY_GROUPS"),
]

GCP_PATHS = [
    ("/computeMetadata/v1/project/project-id", "PROJECT_ID"),
    ("/computeMetadata/v1/project/numeric-project-id", "PROJECT_NUM"),
    ("/computeMetadata/v1/instance/hostname", "HOSTNAME"),
    ("/computeMetadata/v1/instance/zone", "ZONE"),
    ("/computeMetadata/v1/instance/machine-type", "MACHINE_TYPE"),
    ("/computeMetadata/v1/instance/service-accounts/", "SERVICE_ACCOUNTS"),
    ("/computeMetadata/v1/instance/service-accounts/default/email", "SA_EMAIL"),
    ("/computeMetadata/v1/instance/service-accounts/default/token", "SA_TOKEN"),
    ("/computeMetadata/v1/instance/attributes/ssh-keys", "SSH_KEYS"),
    ("/computeMetadata/v1/instance/attributes/kube-env", "KUBE_ENV"),
    ("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", "EXTERNAL_IP"),
]

AZURE_PATHS = [
    ("/metadata/instance?api-version=2021-02-01", "INSTANCE"),
    ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "MANAGED_ID_TOKEN"),
    ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", "KEYVAULT_TOKEN"),
    ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/", "STORAGE_TOKEN"),
    ("/metadata/instance/compute/userData?api-version=2021-01-01&format=text", "USER_DATA"),
]

ORACLE_PATH = "/opc/v2/instance/"
DO_PATH = "/metadata/v1.json"
ALIBABA_PATHS = [
    ("/latest/meta-data/instance-id", "INSTANCE_ID"),
    ("/latest/meta-data/ram/security-credentials/", "RAM_ROLES"),
]


def run(target, ip, open_ports, banners):
    """
    Scanner Cloud Metadata Exposure 2026-Grade — AWS/GCP/Azure/Oracle/DO/Alibaba.

    Técnicas: AWS IMDSv1 (14 paths) + IMDSv2 compliance check,
    GCP (11 paths incl kube-env/external-ip/machine-type),
    Azure IMDS (5 paths incl KeyVault/Storage/UserData tokens),
    Oracle Cloud, DigitalOcean, Alibaba Cloud (RAM roles),
    IAM credential extraction, service account token harvest,
    K8s API access via metadata.
    """
    _ = (target, ip, open_ports, banners, time)
    resultado = {"providers_detectados": [], "vulns": [], "metadados": {}}

    _scan_aws(resultado)
    _scan_aws_v2(resultado)
    _scan_gcp(resultado)
    _scan_azure(resultado)
    _scan_oracle(resultado)
    _scan_do(resultado)
    _scan_alibaba(resultado)

    return {"plugin": "cloud_metadata", "versao": "2026.1", "resultados": resultado}


def _has_provider(resultado, name):
    return any(p["provider"] == name for p in resultado["providers_detectados"])


def _scan_aws(resultado):
    for path, label in AWS_PATHS:
        try:
            resp = requests.get(f"http://169.254.169.254{path}", timeout=3)
            if resp.status_code == 200 and len(resp.text) > 2:
                resultado["metadados"][f"aws_{label}"] = resp.text[:200]
                if label == "IAM_ROLES":
                    _extract_aws_creds(resp.text, resultado)
                if label == "USER_DATA":
                    resultado["vulns"].append({
                        "tipo": "AWS_USER_DATA_EXPOSED", "severidade": "ALTO",
                        "descricao": "User-data exposto — pode conter secrets de bootstrap!",
                    })
                if label == "SECURITY_GROUPS":
                    resultado["vulns"].append({
                        "tipo": "AWS_SG_EXPOSED", "severidade": "MEDIO",
                        "descricao": "Security groups enumeráveis via metadata!",
                    })
                if not _has_provider(resultado, "AWS"):
                    resultado["providers_detectados"].append({"provider": "AWS", "imds_version": "v1"})
        except Exception:
            continue


def _extract_aws_creds(text, resultado):
    role_name = text.strip().split("\n")[0]
    try:
        creds = requests.get(
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
            timeout=3,
        )
        if "AccessKeyId" in creds.text:
            resultado["vulns"].append({
                "tipo": "AWS_CREDENTIALS_EXPOSED", "role": role_name,
                "severidade": "CRITICO",
                "descricao": "AWS IAM credentials via IMDSv1 — full account compromise!",
            })
    except Exception:
        pass


def _scan_aws_v2(resultado):
    try:
        token_resp = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=3,
        )
        if token_resp.status_code == 200:
            v2_resp = requests.get(
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token_resp.text}, timeout=3,
            )
            if v2_resp.status_code == 200:
                if not _has_provider(resultado, "AWS"):
                    resultado["providers_detectados"].append({"provider": "AWS", "imds_version": "v2"})
                resultado["vulns"].append({
                    "tipo": "AWS_IMDSv2_ATIVO", "severidade": "INFO",
                    "descricao": "IMDSv2 ativo — proteção contra SSRF simples",
                })
        elif token_resp.status_code == 403:
            resultado["vulns"].append({
                "tipo": "AWS_IMDSv2_ENFORCED", "severidade": "INFO",
                "descricao": "IMDSv2 enforced — v1 desabilitado (excelente config)",
            })
    except Exception:
        pass


def _scan_gcp(resultado):
    for path, label in GCP_PATHS:
        try:
            resp = requests.get(
                f"http://metadata.google.internal{path}",
                headers={"Metadata-Flavor": "Google"}, timeout=3,
            )
            if resp.status_code == 200:
                resultado["metadados"][f"gcp_{label}"] = resp.text[:200]
                if label == "SA_TOKEN":
                    resultado["vulns"].append({
                        "tipo": "GCP_TOKEN_EXPOSED", "severidade": "CRITICO",
                        "descricao": "GCP SA OAuth token — cloud takeover possível!",
                    })
                elif label == "SSH_KEYS":
                    resultado["vulns"].append({
                        "tipo": "GCP_SSH_KEYS_EXPOSED", "severidade": "CRITICO",
                        "descricao": "SSH keys via metadata — privilege escalation!",
                    })
                elif label == "KUBE_ENV":
                    resultado["vulns"].append({
                        "tipo": "GCP_KUBE_ENV_EXPOSED", "severidade": "CRITICO",
                        "descricao": "Kube-env exposto — K8s service account bootstrap token!",
                    })
                if not _has_provider(resultado, "GCP"):
                    resultado["providers_detectados"].append({"provider": "GCP"})
        except Exception:
            continue


def _scan_azure(resultado):
    for path, label in AZURE_PATHS:
        try:
            resp = requests.get(
                f"http://169.254.169.254{path}",
                headers={"Metadata": "true"}, timeout=3,
            )
            if resp.status_code == 200:
                resultado["metadados"][f"azure_{label}"] = resp.text[:200]
                if "TOKEN" in label and "access_token" in resp.text:
                    resultado["vulns"].append({
                        "tipo": f"AZURE_{label}", "severidade": "CRITICO",
                        "descricao": f"Azure {label} extraído — cloud compromise!",
                    })
                if not _has_provider(resultado, "AZURE"):
                    resultado["providers_detectados"].append({"provider": "AZURE"})
        except Exception:
            continue


def _scan_oracle(resultado):
    try:
        resp = requests.get(
            f"http://169.254.169.254{ORACLE_PATH}",
            headers={"Authorization": "Bearer Oracle"}, timeout=3,
        )
        if resp.status_code == 200 and len(resp.text) > 10:
            resultado["providers_detectados"].append({"provider": "ORACLE"})
            resultado["metadados"]["oracle_instance"] = resp.text[:200]
    except Exception:
        pass


def _scan_do(resultado):
    try:
        resp = requests.get(f"http://169.254.169.254{DO_PATH}", timeout=3)
        if resp.status_code == 200 and "droplet_id" in resp.text:
            resultado["providers_detectados"].append({"provider": "DIGITALOCEAN"})
            resultado["metadados"]["do"] = resp.text[:200]
    except Exception:
        pass


def _scan_alibaba(resultado):
    for path, label in ALIBABA_PATHS:
        try:
            resp = requests.get(f"http://100.100.100.200{path}", timeout=3)
            if resp.status_code == 200 and len(resp.text) > 5:
                if not _has_provider(resultado, "ALIBABA"):
                    resultado["providers_detectados"].append({"provider": "ALIBABA"})
                resultado["metadados"][f"alibaba_{label}"] = resp.text[:200]
                if label == "RAM_ROLES":
                    resultado["vulns"].append({
                        "tipo": "ALIBABA_RAM_ROLES_EXPOSED", "severidade": "CRITICO",
                        "descricao": "Alibaba Cloud RAM roles — credential extraction!",
                    })
        except Exception:
            continue
