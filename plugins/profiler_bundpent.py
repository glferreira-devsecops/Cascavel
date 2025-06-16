# plugins/profiler.py
def run(target, results):
    import subprocess, platform, os

    profile = {}

    # Informações do host (máquina local)
    try:
        uname = platform.uname()
        profile['info_host_local'] = {
            'sistema': uname.system,
            'nome': uname.node,
            'release': uname.release,
            'versao': uname.version,
            'arquitetura': uname.machine,
            'processador': uname.processor
        }
    except Exception as e:
        profile['info_host_local'] = {'erro': str(e)}

    # Nmap: Detecção de SO do alvo
    try:
        nmap_out = subprocess.getoutput(f"nmap -O -T4 {target} | head -30")
        profile['nmap_os_detect'] = nmap_out
    except Exception as e:
        profile['nmap_os_detect'] = f"Erro nmap: {e}"

    # WhatWeb: Fingerprint de tecnologias
    try:
        # Caminho para o whatweb deve estar certo
        whatweb_path = os.path.expanduser("~/WhatWeb/whatweb")
        whatweb_out = subprocess.getoutput(f"{whatweb_path} {target} | head -20")
        profile['whatweb'] = whatweb_out
    except Exception as e:
        profile['whatweb'] = f"Erro whatweb: {e}"

    # SSL Scan
    try:
        sslscan = subprocess.getoutput(f"nmap --script ssl-cert,ssl-enum-ciphers -p 443 {target} | head -40")
        profile['sslscan'] = sslscan
    except Exception as e:
        profile['sslscan'] = f"Erro sslscan: {e}"

    # MITRE ATT&CK Mapping rápido (exemplo)
    profile['mitre_quickmap'] = [
        "Reconhecimento (TA0043): Varredura de portas, descoberta de serviços",
        "Acesso inicial (TA0001): Força bruta, exploração de aplicação pública"
    ]

    results['profiler'] = profile
