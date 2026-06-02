# plugins/websphere_deserialization_rce.py
import requests


def run(target, ip, open_ports, banners):
    """
    Heurística para detectar o CVE-2026-9319 (IBM WebSphere Deserialization RCE).
    Geralmente afeta portas 9080, 9443, etc.
    """
    _ = (ip, banners)

    websphere_ports = [9080, 9443, 9043, 9060]
    portas_alvo = [p for p in open_ports if p in websphere_ports or p in (80, 443)]

    if not portas_alvo:
        return {
            "plugin": "websphere_deserialization_rce",
            "resultados": "Portas do WebSphere não detectadas",
        }

    resultados = []

    for porta in portas_alvo:
        protocolo = "https" if porta in (443, 9443, 9043) else "http"
        url = f"{protocolo}://{target}:{porta}/"

        try:
            resp = requests.get(url, timeout=5, verify=False)  # nosec B501

            # Identificação básica de WebSphere
            if "WebSphere" in resp.text or "WebSphere" in resp.headers.get("Server", ""):
                resultados.append(
                    {
                        "porta": porta,
                        "status": "IBM WebSphere Detectado",
                        "aviso": "Instância WebSphere detectada. Cheque patches para falha crítica de desserialização (CVE-2026-9319).",
                    }
                )
        except requests.exceptions.RequestException:
            pass

    if not resultados:
        return {
            "plugin": "websphere_deserialization_rce",
            "resultados": "Nenhum IBM WebSphere detectado.",
        }

    return {"plugin": "websphere_deserialization_rce", "resultados": resultados}
