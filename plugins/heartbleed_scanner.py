# plugins/heartbleed_scanner.py
import shlex
import shutil
import subprocess


def run(target, ip, open_ports, banners):
    """
    Scanner Heartbleed usando Nmap NSE (CVE-2014-0160).
    Verifica portas SSL/TLS relevantes do alvo. Requer nmap com scripts NSE.
    """
    _ = (ip, banners)

    if not shutil.which("nmap"):
        return {"plugin": "heartbleed_scanner", "resultados": {"erro": "nmap não encontrado no PATH"}}

    safe_target = shlex.quote(target)
    ssl_ports = [p for p in open_ports if p in [443, 8443, 993, 995, 465]] or [443]
    ports_str = ",".join(str(p) for p in ssl_ports)

    resultado = {}
    cmd = f"nmap --script=ssl-heartbleed -p {ports_str} {safe_target}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=30, encoding="utf-8")
        output = proc.stdout + proc.stderr
        resultado["status"] = "VULNERAVEL" if "VULNERABLE" in output else "seguro"
        resultado["detalhes"] = output
    except subprocess.TimeoutExpired:
        resultado["erro"] = "Timeout no scan Heartbleed"
    except Exception as e:
        resultado["erro"] = str(e)

    return {"plugin": "heartbleed_scanner", "resultados": resultado}
