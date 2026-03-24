# plugins/network_mapper.py
import subprocess
import shutil
import shlex


def run(target, ip, open_ports, banners):
    """
    Mapeamento de rede e ASN via asnmap + mapcidr.
    Identifica o ASN do alvo, ranges de IP associados e informações de rede.
    Requer: asnmap e/ou mapcidr instalados no PATH.
    """
    _ = (open_ports, banners)

    resultado = {}
    host_ip = ip if ip and ip != "?" else target
    safe_host = shlex.quote(host_ip)

    # 1. asnmap — Descobre ASN e ranges
    if shutil.which("asnmap"):
        try:
            proc = subprocess.run(
                f"echo {safe_host} | asnmap -silent",
                shell=True, capture_output=True, timeout=30, encoding="utf-8",
            )
            ranges = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            resultado["asn_ranges"] = ranges if ranges else "Nenhum range ASN encontrado"
        except subprocess.TimeoutExpired:
            resultado["asn_ranges"] = "Timeout (30s)"
        except Exception as e:
            resultado["asn_ranges"] = f"Erro: {e}"
    else:
        resultado["asn_ranges"] = "asnmap não encontrado no PATH"

    # 2. mapcidr — Expande ranges CIDR
    if shutil.which("mapcidr") and isinstance(resultado.get("asn_ranges"), list):
        try:
            ranges_input = "\n".join(resultado["asn_ranges"][:3])
            proc = subprocess.run(
                "mapcidr -silent -count",
                input=ranges_input, shell=True, capture_output=True,
                timeout=15, encoding="utf-8",
            )
            resultado["cidr_count"] = proc.stdout.strip()
        except Exception as e:
            resultado["cidr_count"] = f"Erro: {e}"

    # 3. whois básico
    try:
        proc = subprocess.run(
            f"whois {safe_host}",
            shell=True, capture_output=True, timeout=15, encoding="utf-8",
        )
        whois_lines = proc.stdout.splitlines()
        whois_info = {}
        keys = ["OrgName", "Organization", "NetName", "CIDR", "Country", "descr", "origin"]
        for line in whois_lines:
            for key in keys:
                if line.strip().lower().startswith(key.lower()):
                    k, _, v = line.partition(":")
                    whois_info[k.strip()] = v.strip()
        resultado["whois"] = whois_info if whois_info else "Sem informações relevantes"
    except Exception as e:
        resultado["whois"] = f"Erro: {e}"

    return {"plugin": "network_mapper", "resultados": resultado}
