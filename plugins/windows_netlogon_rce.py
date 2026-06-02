# plugins/windows_netlogon_rce.py
import socket


def run(target, ip, open_ports, banners):
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
    except Exception:
        pass

    if not resultados:
        return {
            "plugin": "windows_netlogon_rce",
            "resultados": "Nenhuma exposição RPC vulnerável.",
        }

    return {"plugin": "windows_netlogon_rce", "resultados": resultados}
