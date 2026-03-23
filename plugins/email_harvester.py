# plugins/email_harvester.py
def run(target, ip, open_ports, banners):
    """
    Harvesta endereços de email associados ao domínio alvo.
    Combina scraping web, DNS MX records, e padrões em código-fonte.
    """
    import requests
    import re
    import subprocess

    emails = set()
    resultado = {}

    # Padrão de email
    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

    # 1. Scraping da página principal + subpáginas
    pages = [
        f"http://{target}",
        f"http://{target}/contact",
        f"http://{target}/about",
        f"http://{target}/team",
        f"http://{target}/impressum",
        f"http://{target}/privacy",
        f"http://{target}/legal",
        f"http://{target}/humans.txt",
        f"http://{target}/security.txt",
        f"http://{target}/.well-known/security.txt",
    ]

    for url in pages:
        try:
            resp = requests.get(url, timeout=6)
            if resp.status_code == 200:
                found = email_pattern.findall(resp.text)
                for e in found:
                    # Filtrar falsos positivos (extensões de imagem etc.)
                    if not any(e.lower().endswith(ext) for ext in ['.png', '.jpg', '.gif', '.css', '.js']):
                        emails.add(e.lower())
        except Exception:
            continue

    # 2. DNS MX + SOA
    try:
        mx_out = subprocess.getoutput(f"dig +short MX {target}")
        resultado["mx_records"] = [l.strip() for l in mx_out.splitlines() if l.strip()]
    except Exception:
        resultado["mx_records"] = []

    # 3. Inferir emails comuns
    inferred = [
        f"admin@{target}", f"info@{target}", f"contact@{target}",
        f"support@{target}", f"security@{target}", f"abuse@{target}",
        f"postmaster@{target}", f"webmaster@{target}", f"noreply@{target}",
    ]
    resultado["emails_inferidos"] = inferred

    # 4. Filtrar pelo domínio alvo
    domain_emails = sorted([e for e in emails if target in e])
    other_emails = sorted([e for e in emails if target not in e])

    resultado["emails_do_dominio"] = domain_emails if domain_emails else "Nenhum encontrado"
    resultado["emails_externos"] = other_emails[:20] if other_emails else "Nenhum encontrado"
    resultado["total_unico"] = len(emails)

    return {"plugin": "email_harvester", "resultados": resultado}
