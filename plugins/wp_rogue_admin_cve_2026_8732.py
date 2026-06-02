# plugins/wp_rogue_admin_cve_2026_8732.py
import requests


def run(target, ip, open_ports, banners):
    """
    Scanner heurístico para CVE-2026-8732 (WordPress Plugin AJAX Rogue Admin Creation).
    Vulnerabilidade crítica CVSS 9.8.
    """
    _ = (ip, banners)

    if 80 not in open_ports and 443 not in open_ports:
        return {
            "plugin": "wp_rogue_admin_cve_2026_8732",
            "resultados": "Portas Web não detectadas",
        }

    portas_alvo = [p for p in open_ports if p in (80, 443)]
    resultados = []

    for porta in portas_alvo:
        protocolo = "http" if porta == 80 else "https"
        url = f"{protocolo}://{target}:{porta}/wp-admin/admin-ajax.php"

        try:
            # Enviamos um POST inofensivo para admin-ajax.php
            resp = requests.post(url, data={"action": "heartbeat"}, timeout=5, verify=False)  # nosec B501

            # Se admin-ajax.php está respondendo e é um WP
            if resp.status_code in (200, 400) and ("wp-admin" in resp.text or resp.text == "0"):
                resultados.append(
                    {
                        "porta": porta,
                        "status": "WordPress AJAX Endpoint Exposto",
                        "aviso": "O endpoint admin-ajax.php do WordPress está acessível. Risco de criação de Rogue Admin (CVE-2026-8732) se plugins estiverem desatualizados.",
                    }
                )
        except requests.exceptions.RequestException:
            pass

    if not resultados:
        return {
            "plugin": "wp_rogue_admin_cve_2026_8732",
            "resultados": "Nenhum endpoint WordPress vulnerável detectado.",
        }

    return {"plugin": "wp_rogue_admin_cve_2026_8732", "resultados": resultados}
