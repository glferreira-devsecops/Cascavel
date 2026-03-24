# plugins/wayback_enum.py
import subprocess
import shutil
import shlex
import re


def run(target, ip, open_ports, banners):
    """
    Enumeração de URLs históricas via gau e waybackurls.
    Descobre endpoints antigos, APIs expostas e arquivos sensíveis.
    Requer: gau e/ou waybackurls instalados no PATH.
    """
    _ = (ip, open_ports, banners)

    safe_target = shlex.quote(target)
    urls_encontradas = set()
    resultado = {}

    # Método 1: gau (Get All URLs)
    if shutil.which("gau"):
        try:
            proc = subprocess.run(
                f"echo {safe_target} | gau --threads 3 --blacklist png,jpg,gif,css,woff,ttf,svg",
                shell=True, capture_output=True, timeout=60, encoding="utf-8",
            )
            for url in proc.stdout.splitlines():
                if url.strip():
                    urls_encontradas.add(url.strip())
        except subprocess.TimeoutExpired:
            resultado["gau_status"] = "Timeout (limite: 60s)"
        except Exception as e:
            resultado["gau_erro"] = str(e)
    else:
        resultado["gau_status"] = "gau não encontrado no PATH"

    # Método 2: waybackurls
    if shutil.which("waybackurls"):
        try:
            proc = subprocess.run(
                f"echo {safe_target} | waybackurls",
                shell=True, capture_output=True, timeout=60, encoding="utf-8",
            )
            for url in proc.stdout.splitlines():
                if url.strip():
                    urls_encontradas.add(url.strip())
        except subprocess.TimeoutExpired:
            resultado["waybackurls_status"] = "Timeout (limite: 60s)"
        except Exception as e:
            resultado["waybackurls_erro"] = str(e)
    else:
        resultado["waybackurls_status"] = "waybackurls não encontrado no PATH"

    # Classificar URLs encontradas
    if urls_encontradas:
        sensiveis = [u for u in urls_encontradas if re.search(
            r'\.(php|asp|aspx|jsp|env|config|bak|sql|xml|json|yml|yaml|log|txt|ini|conf)(\?|$)',
            u, re.IGNORECASE,
        )]
        api_endpoints = [u for u in urls_encontradas if re.search(
            r'/api/|/v[0-9]+/|/graphql|/rest/',
            u, re.IGNORECASE,
        )]
        resultado["total_urls"] = len(urls_encontradas)
        resultado["urls_sensiveis"] = sensiveis[:50]
        resultado["api_endpoints"] = api_endpoints[:30]
        resultado["amostra_urls"] = sorted(list(urls_encontradas))[:30]
    else:
        resultado["mensagem"] = "Nenhuma URL histórica encontrada"

    return {"plugin": "wayback_enum", "resultados": resultado}
