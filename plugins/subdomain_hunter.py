# plugins/subdomain_hunter.py
import shlex
import shutil
import subprocess


def run(target, ip, open_ports, banners):
    """
    Enumeração massiva de subdomínios combinando subfinder + amass + httpx.
    Agrega resultados, remove duplicatas, e faz probe HTTP para detectar ativos.
    """
    _ = (ip, open_ports, banners)

    safe_target = shlex.quote(target)
    subdomains = set()
    resultado = {}

    # 1. subfinder
    if shutil.which("subfinder"):
        try:
            proc = subprocess.run(
                f"subfinder -d {safe_target} -silent -all",
                shell=True,
                capture_output=True,
                timeout=90,
                encoding="utf-8",
            )
            for line in proc.stdout.splitlines():
                if line.strip():
                    subdomains.add(line.strip())
            resultado["subfinder_count"] = len(subdomains)
        except subprocess.TimeoutExpired:
            resultado["subfinder"] = "Timeout (90s)"
        except Exception as e:
            resultado["subfinder"] = f"Erro: {e}"
    else:
        resultado["subfinder"] = "não disponível"

    # 2. amass (passive mode para velocidade)
    if shutil.which("amass"):
        try:
            proc = subprocess.run(
                f"amass enum -passive -d {safe_target} -timeout 2",
                shell=True,
                capture_output=True,
                timeout=120,
                encoding="utf-8",
            )
            pre_count = len(subdomains)
            for line in proc.stdout.splitlines():
                if line.strip():
                    subdomains.add(line.strip())
            resultado["amass_novos"] = len(subdomains) - pre_count
        except subprocess.TimeoutExpired:
            resultado["amass"] = "Timeout (120s)"
        except Exception as e:
            resultado["amass"] = f"Erro: {e}"
    else:
        resultado["amass"] = "não disponível"

    # 3. httpx — probe de subdomínios ativos
    ativos = []
    if shutil.which("httpx") and subdomains:
        try:
            subs_input = "\n".join(list(subdomains)[:200])
            proc = subprocess.run(
                "httpx -silent -title -tech-detect -status-code -ip",
                input=subs_input,
                shell=True,
                capture_output=True,
                timeout=120,
                encoding="utf-8",
            )
            ativos = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            resultado["httpx"] = "Timeout (120s)"
        except Exception as e:
            resultado["httpx"] = f"Erro: {e}"

    resultado["total_subdomains"] = len(subdomains)
    resultado["subdomains_ativos"] = ativos[:50] if ativos else "Nenhum ativo detectado"
    resultado["lista_completa"] = sorted(list(subdomains))[:100]

    return {"plugin": "subdomain_hunter", "resultados": resultado}
