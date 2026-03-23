# plugins/heartbleed_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner Heartbleed usando Nmap NSE (CVE-2014-0160).
    Verifica porta 443 (ou portas SSL abertas) do alvo.
    Requer nmap instalado com scripts NSE.
    """
    import subprocess
    import shutil

    if not shutil.which("nmap"):
        return {"plugin": "heartbleed_scanner", "resultados": {"erro": "nmap não encontrado no PATH"}}

    # Verificar portas SSL/TLS relevantes
    ssl_ports = [p for p in open_ports if p in [443, 8443, 993, 995, 465]] or [443]
    ports_str = ",".join(str(p) for p in ssl_ports)

    resultado = {}
    cmd = f"nmap --script=ssl-heartbleed -p {ports_str} {target}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=30, encoding="utf-8")
        output = proc.stdout + proc.stderr
        if "VULNERABLE" in output:
            resultado["status"] = "VULNERAVEL"
            resultado["detalhes"] = output
        else:
            resultado["status"] = "seguro"
            resultado["detalhes"] = output
    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout no scan Heartbleed"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "heartbleed_scanner", "resultados": resultado}
