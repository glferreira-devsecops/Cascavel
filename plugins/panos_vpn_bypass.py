# plugins/panos_vpn_bypass.py
import requests


def run(target, ip, open_ports, banners):
    """
    Detector heurístico para CVE-2026-0257 (Palo Alto PAN-OS GlobalProtect Auth Bypass).
    A vulnerabilidade permite o estabelecimento de conexões VPN não autorizadas.
    """
    _ = (ip, banners)

    # GlobalProtect portal costuma rodar em 443/TCP
    if 443 not in open_ports and 80 not in open_ports and 8443 not in open_ports:
        return {
            "plugin": "panos_vpn_bypass",
            "resultados": "Portas HTTPS não detectadas",
        }

    portas_alvo = [p for p in open_ports if p in (80, 443, 8443, 10443)]

    resultados = []

    for porta in portas_alvo:
        protocolo = "http" if porta == 80 else "https"
        url = f"{protocolo}://{target}:{porta}/global-protect/login.esp"

        try:
            # Requisicao inofensiva para detectar presença do endpoint
            # Em cenários reais, enviar payloads de teste para verificar se há auth bypass
            resp = requests.get(url, timeout=5, verify=False)  # nosec B501

            if resp.status_code == 200 and "GlobalProtect" in resp.text:
                resultados.append(
                    {
                        "porta": porta,
                        "status": "Portal GlobalProtect Detectado",
                        "aviso": "O endpoint /global-protect/login.esp está ativo. Recomenda-se verificação imediata de patch para CVE-2026-0257.",
                    }
                )
        except requests.exceptions.RequestException:
            pass

    if not resultados:
        return {
            "plugin": "panos_vpn_bypass",
            "resultados": "Nenhum portal GlobalProtect vulnerável detectado.",
        }

    return {"plugin": "panos_vpn_bypass", "resultados": resultados}
