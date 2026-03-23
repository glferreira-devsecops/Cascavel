# plugins/subdomain_takeou.py
def run(target, ip, open_ports, banners):
    """
    Enumera possíveis subdomínios vulneráveis a takeover.
    Usa fingerprints comuns de serviços SaaS e cloud.
    """
    import requests

    subdominios = [
        f"dev.{target}", f"test.{target}", f"staging.{target}",
        f"beta.{target}", f"app.{target}", f"api.{target}",
        f"mail.{target}", f"cdn.{target}", f"status.{target}",
        f"docs.{target}", f"shop.{target}", f"blog.{target}",
    ]
    fingerprints = [
        "There is no such app",
        "NoSuchBucket",
        "is not configured",
        "herokucdn.com error",
        "This CNAME does not resolve",
        "Sorry, this shop is currently unavailable",
        "Repository not found",
        "The specified bucket does not exist",
        "Domain is not configured",
        "This page is parked",
    ]
    takeover = []

    for sub in subdominios:
        try:
            resposta = requests.get(f"http://{sub}", timeout=6, allow_redirects=True)
            for fp in fingerprints:
                if fp.lower() in resposta.text.lower():
                    takeover.append({
                        "subdominio": sub,
                        "indicador": fp,
                        "status_http": resposta.status_code,
                    })
        except requests.ConnectionError:
            # NXDOMAIN ou host unreachable — pode indicar takeover potencial
            takeover.append({
                "subdominio": sub,
                "indicador": "DNS_NXDOMAIN_OU_UNREACHABLE",
                "status_http": None,
            })
        except Exception:
            pass

    return {
        "plugin": "subdomain_takeou",
        "resultados": takeover if takeover else "Nenhum takeover óbvio detectado"
    }
