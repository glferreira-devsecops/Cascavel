# plugins/s3_bucket_enum.py
def run(target, results):
    """
    Enumera buckets públicos S3 relacionados ao domínio alvo.
    Busca padrões comuns e retorna a lista de buckets abertos encontrados.
    """
    import requests
    buckets = [
        f"{target}",
        f"files.{target}",
        f"cdn.{target}",
        f"static.{target}",
        f"media.{target}",
        f"backup.{target}"
    ]
    buckets_ok = []

    for bucket in buckets:
        url = f"http://{bucket}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=7)
            if "ListBucketResult" in r.text and "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"" in r.text:
                buckets_ok.append({"bucket": bucket, "url": url})
        except Exception:
            continue

    results["s3_bucket_enum"] = buckets_ok if buckets_ok else "Nenhum bucket S3 aberto encontrado"
