# plugins/heartbleed_scanner.py
def run(target, results):
    """
    Scanner Heartbleed usando Nmap. Busca CVE-2014-0160.
    Requer nmap instalado e permissão para rodar scripts NSE.
    """
    import subprocess
    cmd = f"nmap --script=ssl-heartbleed -p 443 {target}"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=20)
        results["heartbleed"] = output.decode()
    except Exception as e:
        results["heartbleed"] = {"error": str(e)}
