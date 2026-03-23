# plugins/wifi_attac.py
def run(target, ip, open_ports, banners):
    """
    Plugin de reconhecimento wireless: scan de redes Wi-Fi.
    Detecta OS e disponibilidade de ferramentas antes de executar.
    target: ignorado (operação local)
    Requer root/sudo e ferramentas aircrack-ng.
    """
    import subprocess
    import re
    import platform
    import shutil
    import os

    resultado = {}
    sistema = platform.system()

    # Verificar se está rodando como root
    if os.geteuid() != 0:
        return {
            "plugin": "wifi_attac",
            "resultados": {"aviso": "Requer execução como root (sudo). Skipping."}
        }

    if sistema == "Darwin":
        # macOS: usar airport para scan
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if not os.path.isfile(airport_path):
            return {"plugin": "wifi_attac", "resultados": {"erro": "airport não encontrado (macOS)"}}

        try:
            proc = subprocess.run(
                f"{airport_path} -s", shell=True, capture_output=True,
                timeout=15, encoding="utf-8"
            )
            redes = []
            for line in proc.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    redes.append({
                        "ssid": parts[0],
                        "bssid": parts[1],
                        "rssi": parts[2],
                        "channel": parts[3],
                        "security": " ".join(parts[6:]),
                    })
            resultado["redes_encontradas"] = redes if redes else "Nenhuma rede encontrada"
        except Exception as e:
            resultado["erro"] = str(e)

    elif sistema == "Linux":
        # Linux: usar iw + airodump-ng
        if not shutil.which("iw"):
            return {"plugin": "wifi_attac", "resultados": {"erro": "iw não encontrado no PATH"}}

        iw_out = subprocess.getoutput("iw dev")
        interfaces = re.findall(r'Interface\s+([^\s]+)', iw_out)
        if not interfaces:
            return {"plugin": "wifi_attac", "resultados": {"erro": "Nenhuma interface wireless detectada"}}

        iface = interfaces[0]
        resultado["interface"] = iface

        # Scan via iw (sem precisar de aircrack-ng)
        try:
            scan_out = subprocess.getoutput(f"sudo iw dev {iface} scan 2>/dev/null")
            ssids = re.findall(r'SSID:\s+(.+)', scan_out)
            bssids = re.findall(r'BSS\s+([0-9a-fA-F:]{17})', scan_out)
            redes = [{"bssid": b, "ssid": s} for b, s in zip(bssids, ssids)]
            resultado["redes_encontradas"] = redes if redes else "Nenhuma rede encontrada"
        except Exception as e:
            resultado["erro"] = str(e)
    else:
        resultado["erro"] = f"OS não suportado: {sistema}"

    return {"plugin": "wifi_attac", "resultados": resultado}
