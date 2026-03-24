# plugins/profiler_bundpent.py
import subprocess
import platform
import shutil
import shlex


def run(target, ip, open_ports, banners):
    """
    Profiler completo: info do host local, OS detection via nmap,
    fingerprint via whatweb (se disponível), SSL scan e mapeamento MITRE ATT&CK.
    """
    _ = (ip, open_ports, banners)
    profile = {}
    safe_target = shlex.quote(target)

    # 1. Informações do host local
    try:
        uname = platform.uname()
        profile["info_host_local"] = {
            "sistema": uname.system,
            "nome": uname.node,
            "release": uname.release,
            "versao": uname.version,
            "arquitetura": uname.machine,
            "processador": uname.processor,
        }
    except Exception as e:
        profile["info_host_local"] = {"erro": str(e)}

    # 2. Nmap: Detecção de SO do alvo
    if shutil.which("nmap"):
        try:
            proc = subprocess.run(
                f"nmap -O -T4 {safe_target}",
                shell=True, capture_output=True, timeout=60, encoding="utf-8",
            )
            profile["nmap_os_detect"] = proc.stdout[:2000]
        except subprocess.TimeoutExpired:
            profile["nmap_os_detect"] = "Timeout na detecção de OS"
        except Exception as e:
            profile["nmap_os_detect"] = f"Erro nmap: {e}"
    else:
        profile["nmap_os_detect"] = "nmap não encontrado no PATH"

    # 3. WhatWeb: Fingerprint de tecnologias
    whatweb_bin = shutil.which("whatweb")
    if whatweb_bin:
        try:
            proc = subprocess.run(
                f"{whatweb_bin} {safe_target}",
                shell=True, capture_output=True, timeout=30, encoding="utf-8",
            )
            profile["whatweb"] = proc.stdout[:2000]
        except subprocess.TimeoutExpired:
            profile["whatweb"] = "Timeout no WhatWeb"
        except Exception as e:
            profile["whatweb"] = f"Erro whatweb: {e}"
    else:
        profile["whatweb"] = "whatweb não encontrado no PATH"

    # 4. SSL Scan
    if shutil.which("nmap"):
        try:
            proc = subprocess.run(
                f"nmap --script ssl-cert,ssl-enum-ciphers -p 443 {safe_target}",
                shell=True, capture_output=True, timeout=30, encoding="utf-8",
            )
            profile["sslscan"] = proc.stdout[:2000]
        except subprocess.TimeoutExpired:
            profile["sslscan"] = "Timeout no SSL scan"
        except Exception as e:
            profile["sslscan"] = f"Erro sslscan: {e}"

    # 5. MITRE ATT&CK Mapping
    profile["mitre_quickmap"] = [
        "Reconhecimento (TA0043): Varredura de portas, descoberta de serviços",
        "Acesso inicial (TA0001): Força bruta, exploração de aplicação pública",
        "Descoberta (TA0007): Detecção de SO, fingerprint de tecnologias",
    ]

    return {"plugin": "profiler_bundpent", "resultados": profile}
