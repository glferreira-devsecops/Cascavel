# plugins/waf_detect.py
def run(target, results):
    """
    Detecta presença de Web Application Firewall (WAF) de forma heurística.
    Analisa respostas HTTP suspeitas a payloads típicos de SQLi.
    """
    import requests

    try:
        url = f"http://{target}/?id=' OR 1=1--"
        resp = requests.get(url, timeout=5)
        indicativos = [
            "Access Denied", "WAF", "Request blocked", "Firewall", "Malicious", "Blocked"
        ]
        status_waf = False
        for ind in indicativos:
            if ind.lower() in resp.text.lower():
                status_waf = True
                break
        if resp.status_code in [403, 406, 501, 999]:
            status_waf = True

        results["waf_detect"] = "WAF detectado" if status_waf else "Nenhum WAF óbvio detectado"
    except Exception as e:
        results["waf_detect"] = {"erro": str(e)}
