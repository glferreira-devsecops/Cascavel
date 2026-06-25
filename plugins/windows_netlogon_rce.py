# plugins/windows_netlogon_rce.py
import logging
import socket

logger = logging.getLogger(__name__)


def run(target, ip, open_ports, banners, context=None):
    """
    Verificador heurístico para Netlogon RCE (CVE-2026-41089).
    A vulnerabilidade afeta Domain Controllers via RPC no Netlogon.
    """
    _ = (ip, banners)

    # RPC endpoint mapper
    if 135 not in open_ports and 445 not in open_ports:
        return {
            "plugin": "windows_netlogon_rce",
            "resultados": "Portas RPC/SMB fechadas, não vulnerável.",
        }

    resultados = []

    # Heurística básica: checando exposição do RPC
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        res = s.connect_ex((target, 135))
        if res == 0:
            resultados.append(
                {
                    "porta": 135,
                    "status": "RPC Endpoint Mapper Exposto",
                    "aviso": "Serviços RPC expostos. Em Domain Controllers, certifique-se de aplicar patch para CVE-2026-41089 (Netlogon RCE).",
                }
            )
        s.close()
    except Exception as _exc:
        logger.debug("Non-critical error: %s", _exc)

    if not resultados:
        return {
            "plugin": "windows_netlogon_rce",
            "resultados": "Nenhuma exposição RPC vulnerável.",
        }

    return {"plugin": "windows_netlogon_rce", "resultados": resultados}
