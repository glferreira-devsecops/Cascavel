# plugins/katana_crawler.py
def run(target, ip, open_ports, banners):
    """
    Web crawler moderno via ProjectDiscovery Katana.
    Crawl ativo do alvo para descobrir endpoints, forms, links e JS files.
    Requer: katana instalado no PATH.
    """
    import subprocess
    import shutil
    import re

    if not shutil.which("katana"):
        return {"plugin": "katana_crawler", "resultados": {"erro": "katana não encontrado no PATH"}}

    resultado = {}
    try:
        cmd = f"echo http://{target} | katana -silent -d 3 -jc -kf all -ct 60"
        proc = subprocess.run(
            cmd, shell=True, capture_output=True,
            timeout=90, encoding="utf-8"
        )
        urls = [l.strip() for l in proc.stdout.splitlines() if l.strip()]

        if urls:
            # Classificar resultados
            js_files = [u for u in urls if re.search(r'\.js(\?|$)', u, re.IGNORECASE)]
            forms = [u for u in urls if re.search(r'\?(.*=)', u)]
            api_endpoints = [u for u in urls if re.search(r'/api/|/v[0-9]+/|/graphql', u, re.IGNORECASE)]

            resultado["total_urls"] = len(urls)
            resultado["js_files"] = js_files[:20]
            resultado["forms_parametros"] = forms[:30]
            resultado["api_endpoints"] = api_endpoints[:20]
            resultado["amostra"] = urls[:30]
        else:
            resultado["mensagem"] = "Nenhuma URL encontrada pelo crawler"

    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout (limite: 90s)"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "katana_crawler", "resultados": resultado}
