# plugins/advanced_nmap.py
def run(target, results):
    """
    Varredura Nmap avançada (all ports, scripts, banners), saída em JSON se possível.
    Requer nmap 7.80+ (para -oJ). Garante máxima performance.
    """
    import subprocess, json

    nmap_cmd = f"nmap -sC -sV -p- --min-rate 5000 -T4 {target} -oJ -"
    try:
        # Usa getoutput, que já retorna saída como string
        nmap_out = subprocess.getoutput(nmap_cmd)
        try:
            nmap_json = json.loads(nmap_out)
        except Exception:
            # Se não for JSON (ex: nmap velho), retorna string mesmo
            nmap_json = nmap_out
        results['advanced_nmap'] = nmap_json
    except Exception as e:
        results['advanced_nmap'] = {'error': str(e)}
