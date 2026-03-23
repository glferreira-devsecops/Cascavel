# plugins/s3_bucket.py
def run(target, ip, open_ports, banners):
    """
    Enumera buckets públicos S3 relacionados ao domínio alvo.
    Busca padrões comuns e retorna a lista de buckets abertos encontrados.
    """
    import requests

    prefixes = [
        target.replace(".", "-"),
        target.split(".")[0],
        f"files-{target.split('.')[0]}",
        f"cdn-{target.split('.')[0]}",
        f"static-{target.split('.')[0]}",
        f"media-{target.split('.')[0]}",
        f"backup-{target.split('.')[0]}",
        f"assets-{target.split('.')[0]}",
        f"data-{target.split('.')[0]}",
    ]
    buckets_ok = []

    for bucket in prefixes:
        url = f"http://{bucket}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=7)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                buckets_ok.append({"bucket": bucket, "url": url, "status": "ABERTO"})
            elif r.status_code == 403:
                buckets_ok.append({"bucket": bucket, "url": url, "status": "EXISTE_MAS_PRIVADO"})
        except Exception:
            continue

    return {
        "plugin": "s3_bucket",
        "resultados": buckets_ok if buckets_ok else "Nenhum bucket S3 encontrado"
    }
