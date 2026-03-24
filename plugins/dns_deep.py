# plugins/dns_deep.py
import subprocess
import shutil
import shlex


def run(target, ip, open_ports, banners):
    """
    DNS profundo: integra dnsx, dnsrecon e fierce para enumeração DNS completa.
    Descobre registros DNS, zone transfers, subdomínios e nameservers.
    """
    _ = (ip, open_ports, banners)

    safe_target = shlex.quote(target)
    resultado = {}

    # 1. dnsx — resolução DNS em massa
    if shutil.which("dnsx"):
        try:
            proc = subprocess.run(
                f"echo {safe_target} | dnsx -silent -a -aaaa -mx -ns -cname -txt -soa -resp",
                shell=True, capture_output=True, timeout=30, encoding="utf-8",
            )
            registros = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            resultado["dnsx"] = registros if registros else "Sem resultados"
        except subprocess.TimeoutExpired:
            resultado["dnsx"] = "Timeout (30s)"
        except Exception as e:
            resultado["dnsx"] = f"Erro: {e}"
    else:
        resultado["dnsx"] = "dnsx não encontrado no PATH"

    # 2. dnsrecon — reconhecimento DNS completo
    if shutil.which("dnsrecon"):
        try:
            proc = subprocess.run(
                f"dnsrecon -d {safe_target} -t std,brt,axfr",
                shell=True, capture_output=True, timeout=60, encoding="utf-8",
            )
            resultado["dnsrecon"] = proc.stdout[:3000] if proc.stdout else "Sem resultados"
        except subprocess.TimeoutExpired:
            resultado["dnsrecon"] = "Timeout (60s)"
        except Exception as e:
            resultado["dnsrecon"] = f"Erro: {e}"
    else:
        resultado["dnsrecon"] = "dnsrecon não encontrado no PATH"

    # 3. fierce — enumeração de subdomínios via DNS
    if shutil.which("fierce"):
        try:
            proc = subprocess.run(
                f"fierce --domain {safe_target}",
                shell=True, capture_output=True, timeout=60, encoding="utf-8",
            )
            resultado["fierce"] = proc.stdout[:3000] if proc.stdout else "Sem resultados"
        except subprocess.TimeoutExpired:
            resultado["fierce"] = "Timeout (60s)"
        except Exception as e:
            resultado["fierce"] = f"Erro: {e}"
    else:
        resultado["fierce"] = "fierce não encontrado no PATH"

    # 4. dig — registros específicos
    try:
        registros = {}
        for tipo in ["A", "MX", "NS", "TXT", "CNAME", "SOA"]:
            proc = subprocess.run(
                f"dig +short {safe_target} {tipo}",
                shell=True, capture_output=True, timeout=10, encoding="utf-8",
            )
            registros[tipo] = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        resultado["dig_records"] = registros
    except Exception as e:
        resultado["dig_records"] = f"Erro: {e}"

    return {"plugin": "dns_deep", "resultados": resultado}
