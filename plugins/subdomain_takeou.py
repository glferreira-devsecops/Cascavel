# plugins/subdomain_takeover.py
def run(target, results):
    """
    Enumera possíveis subdomínios vulneráveis a takeover.
    Usa fingerprints comuns de serviços SaaS e cloud.
    """
    import requests

    subdominios = [f"dev.{target}", f"test.{target}", f"staging.{target}"]
    fingerprints = [
        "There is no such app",
        "NoSuchBucket",
        "is not configured",
        "herokucdn.com error",
        "This CNAME does not resolve",
        "Sorry, this shop is currently unavailable",
        "Repository not found",
        "404 Not Found"
    ]
    takeover = []

    for sub in subdominios:
        try:
            resposta = requests.get(f"http://{sub}", timeout=6)
            for fp in fingerprints:
                if fp in resposta.text:
                    takeover.append({"subdominio": sub, "indicador": fp})
        except Exception:
            pass

    results["subdomain_takeover"] = takeover if takeover else "Nenhum takeover óbvio detectado"
