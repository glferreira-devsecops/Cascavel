# plugins/waf_detec.py
def run(target, ip, open_ports, banners):
    """
    Detecta presença de Web Application Firewall (WAF) de forma heurística.
    Analisa respostas HTTP suspeitas a payloads típicos de SQLi/XSS.
    """
    import requests
    import shutil
    import subprocess

    resultado = {}

    # Método 1: Heurística manual
    test_payloads = [
        f"http://{target}/?id=' OR 1=1--",
        f"http://{target}/?q=<script>alert(1)</script>",
        f"http://{target}/../../etc/passwd",
    ]
    indicativos = [
        "access denied", "waf", "request blocked", "firewall", "malicious",
        "blocked", "forbidden", "cloudflare", "akamai", "incapsula",
        "sucuri", "f5 big-ip", "mod_security", "request rejected",
    ]

    deteccoes = []
    for url in test_payloads:
        try:
            resp = requests.get(url, timeout=5)
            for ind in indicativos:
                if ind in resp.text.lower():
                    deteccoes.append({"url": url, "indicador": ind, "status": resp.status_code})
                    break
            if resp.status_code in [403, 406, 501, 999]:
                deteccoes.append({"url": url, "indicador": f"HTTP_{resp.status_code}", "status": resp.status_code})
        except Exception:
            continue

    resultado["heuristica"] = deteccoes if deteccoes else "Nenhum WAF detectado via heurística"

    # Método 2: wafw00f (se disponível)
    if shutil.which("wafw00f"):
        try:
            proc = subprocess.run(
                f"wafw00f {target}", shell=True, capture_output=True,
                timeout=20, encoding="utf-8"
            )
            resultado["wafw00f"] = proc.stdout[:1500]
        except Exception as e:
            resultado["wafw00f"] = f"Erro: {e}"

    return {"plugin": "waf_detec", "resultados": resultado}
