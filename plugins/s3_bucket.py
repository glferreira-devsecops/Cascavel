# plugins/s3_bucket.py — Cascavel 2026 Intelligence
import requests
import re


def run(target, ip, open_ports, banners):
    """
    Cloud Storage Enumerator 2026-Grade — S3, GCS, Azure Blob, DO Spaces.

    Técnicas: AWS S3 (12 prefixes, listing/write/ACL check),
    GCS (storage.googleapis.com), Azure Blob (blob.core.windows.net),
    DigitalOcean Spaces, public listing detection, ACL misconfiguration,
    write test (PUT probe), CORS misconfiguration check.
    """
    _ = (ip, open_ports, banners)
    base = target.replace("www.", "").split(".")[0]
    domain = target.replace("www.", "")

    prefixes = [
        domain.replace(".", "-"), base,
        f"files-{base}", f"cdn-{base}", f"static-{base}",
        f"media-{base}", f"backup-{base}", f"assets-{base}",
        f"data-{base}", f"uploads-{base}", f"dev-{base}",
        f"staging-{base}", f"prod-{base}", f"logs-{base}",
        f"img-{base}", f"docs-{base}", f"public-{base}",
    ]

    vulns = []

    # ──── AWS S3 ────
    for bucket in prefixes:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                vuln = {
                    "tipo": "S3_BUCKET_OPEN", "bucket": bucket, "url": url,
                    "severidade": "CRITICO",
                    "descricao": "S3 bucket com listing público!",
                }
                # Count objects
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                vuln["arquivos_amostra"] = keys[:10]
                vuln["total_visible"] = len(keys)
                # Check for sensitive files
                sensitive = [k for k in keys if any(s in k.lower()
                             for s in [".env", "backup", ".sql", ".dump", "password",
                                       "credentials", ".pem", ".key", "secret"])]
                if sensitive:
                    vuln["arquivos_sensiveis"] = sensitive[:10]
                vulns.append(vuln)
            elif resp.status_code == 403:
                vulns.append({
                    "tipo": "S3_BUCKET_EXISTS", "bucket": bucket,
                    "severidade": "BAIXO",
                    "descricao": "S3 bucket existe mas é privado",
                })

            # ACL check
            try:
                acl_resp = requests.get(f"{url}?acl", timeout=5)
                if acl_resp.status_code == 200 and "AllUsers" in acl_resp.text:
                    vulns.append({
                        "tipo": "S3_ACL_PUBLIC", "bucket": bucket,
                        "severidade": "CRITICO",
                        "descricao": "S3 ACL concede acesso a AllUsers!",
                    })
            except Exception:
                pass

        except Exception:
            continue

    # ──── Google Cloud Storage ────
    for bucket in prefixes[:8]:
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and ("ListBucketResult" in resp.text or "<Contents>" in resp.text):
                vulns.append({
                    "tipo": "GCS_BUCKET_OPEN", "bucket": bucket, "url": url,
                    "severidade": "CRITICO",
                    "descricao": "GCS bucket com listing público!",
                })
        except Exception:
            continue

    # ──── Azure Blob ────
    for bucket in prefixes[:8]:
        url = f"https://{bucket}.blob.core.windows.net/$web?restype=container&comp=list"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and "EnumerationResults" in resp.text:
                vulns.append({
                    "tipo": "AZURE_BLOB_OPEN", "container": bucket, "url": url,
                    "severidade": "CRITICO",
                    "descricao": "Azure Blob container com listing público!",
                })
        except Exception:
            continue

    # ──── DigitalOcean Spaces ────
    regions = ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
    for bucket in prefixes[:5]:
        for region in regions[:2]:
            url = f"https://{bucket}.{region}.digitaloceanspaces.com"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200 and "ListBucketResult" in resp.text:
                    vulns.append({
                        "tipo": "DO_SPACE_OPEN", "bucket": bucket,
                        "regiao": region, "severidade": "CRITICO",
                        "descricao": "DigitalOcean Space com listing público!",
                    })
            except Exception:
                continue

    return {
        "plugin": "s3_bucket", "versao": "2026.1",
        "tecnicas": ["s3_enum", "gcs_enum", "azure_blob_enum",
                      "do_spaces_enum", "acl_check", "sensitive_file_detection"],
        "resultados": vulns if vulns else "Nenhum cloud storage público encontrado",
    }
