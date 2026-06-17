# plugins/ghost_cms_sqli.py
import requests


def run(target, ip, open_ports, banners, context=None):
    """
    Identificador para a injeção SQL cega crítica (CVE-2026-26980) afetando Ghost CMS.
    """
    _ = (ip, banners)

    if 80 not in open_ports and 443 not in open_ports and 2368 not in open_ports:
        return {"plugin": "ghost_cms_sqli", "resultados": "Portas Web não detectadas"}

    portas_alvo = [p for p in open_ports if p in (80, 443, 2368)]
    resultados = []

    for porta in portas_alvo:
        protocolo = "http" if porta in (80, 2368) else "https"
        url = f"{protocolo}://{target}:{porta}/ghost/api/v3/content/settings/"

        try:
            resp = requests.get(url, timeout=5, verify=False)  # nosec B501

            # Heurística para Ghost CMS API V3 e V4 (Vulneráveis se desatualizados)
            if resp.status_code in (200, 401, 403) and (
                "Ghost" in resp.text or "ghost" in resp.headers.get("X-Powered-By", "").lower()
            ):
                resultados.append(
                    {
                        "porta": porta,
                        "status": "Instância Ghost CMS API Detectada",
                        "aviso": "Ghost CMS detectado. Verifique a versão para mitigar injeção SQL crítica (CVE-2026-26980).",
                    }
                )
        except requests.exceptions.RequestException:
            pass

    if not resultados:
        return {
            "plugin": "ghost_cms_sqli",
            "resultados": "Nenhum endpoint vulnerável do Ghost CMS detectado.",
        }

    return {"plugin": "ghost_cms_sqli", "resultados": resultados}
