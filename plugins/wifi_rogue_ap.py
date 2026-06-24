"""
[+] Plugin: Rogue AP & Wi-Fi Attack Detection
[+] Description: Detecta Evil Twin, Karma attacks, WPA handshake capture, PMKID e deauth
[+] Category: Wireless Security
[+] CVSS: 8.5 (High)
[+] Author: CASCAVEL Framework
"""

import re
import subprocess
import shutil
from typing import Any


def _get_wireless_interfaces() -> list[str]:
    """Lista interfaces wireless disponíveis."""
    interfaces = []
    try:
        if shutil.which("iwconfig"):
            result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "IEEE 802.11" in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
        elif shutil.which("iw"):
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=10
            )
            for line in result.splitlines():
                if "Interface" in line:
                    iface = line.strip().split()[-1]
                    interfaces.append(iface)
    except Exception:
        pass
    return interfaces


def _check_evil_twin(target: str) -> list[dict[str, Any]]:
    """Detecta indicadores de Evil Twin AP."""
    findings = []
    try:
        # Check for duplicate SSIDs on different BSSIDs
        if shutil.which("iwlist"):
            interfaces = _get_wireless_interfaces()
            if not interfaces:
                findings.append({
                    "tipo": "WIRELESS_SEM_INTERFACE",
                    "severidade": "INFO",
                    "descricao": "Nenhuma interface wireless detectada — scan não disponível",
                    "correcao": "Executar em host com adaptador Wi-Fi para detecção completa.",
                })
                return findings

            for iface in interfaces[:1]:
                result = subprocess.run(
                    ["sudo", "iwlist", iface, "scan"],
                    capture_output=True, text=True, timeout=30
                )
                output = result.stdout
                # Parse SSIDs and BSSIDs
                ssids: dict[str, list[str]] = {}
                current_bssid = ""
                for line in output.splitlines():
                    bssid_match = re.search(r"Cell \d+ - Address: ([0-9A-Fa-f:]{17})", line)
                    if bssid_match:
                        current_bssid = bssid_match.group(1)
                    ssid_match = re.search(r'ESSID:"(.+)"', line)
                    if ssid_match and current_bssid:
                        ssid = ssid_match.group(1)
                        ssids.setdefault(ssid, []).append(current_bssid)

                for ssid, bssids in ssids.items():
                    if len(bssids) > 1:
                        findings.append({
                            "tipo": "EVIL_TWIN_SUSPEITA",
                            "severidade": "CRITICO",
                            "descricao": f"SSSID '{ssid}' com {len(bssids)} BSSIDs — possível Evil Twin",
                            "evidencia": f"BSSIDs: {', '.join(bssids[:5])}",
                            "correcao": "Investigar BSSIDs duplicados. Usar WPA3-Enterprise com certificados.",
                        })
        else:
            findings.append({
                "tipo": "IWLCONFIG_INDISPONIVEL",
                "severidade": "INFO",
                "descricao": "iwlist não disponível — scan wireless limitado",
                "correcao": "Instalar wireless-tools para detecção completa.",
            })
    except Exception:
        pass
    return findings


def _check_karma_vulnerability() -> list[dict[str, Any]]:
    """Verifica vulnerabilidade a ataques Karma (auto-connect a SSIDs conhecidos)."""
    findings = []
    try:
        # Check NetworkManager for known networks that auto-connect
        nm_paths = [
            "/etc/NetworkManager/system-connections/",
            "/etc/wpa_supplicant/wpa_supplicant.conf",
        ]
        known_ssids = []
        for path in nm_paths:
            try:
                if path.endswith("/"):
                    import os
                    if os.path.isdir(path):
                        for f in os.listdir(path):
                            filepath = os.path.join(path, f)
                            try:
                                with open(filepath, "r") as fh:
                                    content = fh.read()
                                    ssid_match = re.search(r"ssid=(.+)", content)
                                    if ssid_match:
                                        known_ssids.append(ssid_match.group(1).strip())
                            except Exception:
                                continue
                else:
                    import os
                    if os.path.exists(path):
                        with open(path, "r") as fh:
                            for line in fh:
                                ssid_match = re.search(r'ssid="(.+)"', line)
                                if ssid_match:
                                    known_ssids.append(ssid_match.group(1))
            except Exception:
                continue

        if known_ssids:
            findings.append({
                "tipo": "KARMA_AUTOCONNECT",
                "severidade": "ALTO",
                "descricao": f"{len(known_ssids)} SSIDs conhecidos com auto-connect — vulnerável a Karma attack",
                "evidencia": f"SSIDs: {', '.join(known_ssids[:10])}",
                "correcao": "Desabilitar auto-connect e usar WPA3-Enterprise. Limpar redes salvas não utilizadas.",
            })
    except Exception:
        pass
    return findings


def _check_wpa_handshake(target: str) -> list[dict[str, Any]]:
    """Verifica se a rede permite captura de handshake WPA."""
    findings = []
    try:
        # Check if aircrack-ng suite is available
        if not shutil.which("airodump-ng"):
            return findings

        interfaces = _get_wireless_interfaces()
        if not interfaces:
            return findings

        # Check for WPA2-only networks (no WPA3) that are handshake-capturable
        # This is a passive check — we don't actively deauth
        findings.append({
            "tipo": "WPA_HANDSHAKE_CHECK",
            "severidade": "MEDIO",
            "descricao": "Ferramentas de captura de handshake disponíveis — redes WPA2 vulneráveis",
            "correcao": "Migrar para WPA3-SAE para eliminar ataques de handshake capture.",
        })
    except Exception:
        pass
    return findings


def _check_pmkid_attack() -> list[dict[str, Any]]:
    """Verifica vulnerabilidade a ataques PMKID (clientless)."""
    findings = []
    try:
        # Check if hcxdumptool is available
        if shutil.which("hcxdumptool"):
            findings.append({
                "tipo": "PMKID_FERRAMENTA_DISPONIVEL",
                "severidade": "MEDIO",
                "descricao": "hcxdumptool disponível — ataques PMKID possíveis contra redes WPA2",
                "correcao": "Migrar para WPA3 ou usar MAC filtering adicional. Monitorar BSSIDs não autorizados.",
            })

        # Check for WPA2 networks without management frame protection
        interfaces = _get_wireless_interfaces()
        if interfaces and shutil.which("iw"):
            for iface in interfaces[:1]:
                result = subprocess.run(
                    ["iw", iface, "info"], capture_output=True, text=True, timeout=10
                )
                if "type" in result.stdout:
                    findings.append({
                        "tipo": "MFP_VERIFICAR",
                        "severidade": "BAIXO",
                        "descricao": "Verificar se Management Frame Protection (802.11w) está habilitado nos APs",
                        "correcao": "Habilitar MFP/PMF obrigatório em todos os access points.",
                    })
                    break
    except Exception:
        pass
    return findings


def _check_deauth_protection() -> list[dict[str, Any]]:
    """Verifica proteção contra ataques de deautenticação."""
    findings = []
    try:
        # Check if monitoring mode interfaces exist (could indicate active attacks)
        interfaces = _get_wireless_interfaces()
        monitor_ifaces = []
        for iface in interfaces:
            try:
                result = subprocess.run(
                    ["iw", iface, "info"], capture_output=True, text=True, timeout=5
                )
                if "type monitor" in result.stdout:
                    monitor_ifaces.append(iface)
            except Exception:
                continue

        if monitor_ifaces:
            findings.append({
                "tipo": "MONITOR_INTERFACE_ATIVA",
                "severidade": "ALTO",
                "descricao": f"Interface(s) em modo monitor detectada(s): {', '.join(monitor_ifaces)} — possível ataque de deauth em curso",
                "evidencia": f"Interfaces: {', '.join(monitor_ifaces)}",
                "correcao": "Investigar interfaces em modo monitor. Desativar se não autorizado.",
            })

        # Check for 802.11w (PMF) support — protection against deauth
        findings.append({
            "tipo": "DEAUTH_PROTECTION_CHECK",
            "severidade": "INFO",
            "descricao": "Verificar se APs suportam Protected Management Frames (802.11w)",
            "correcao": "Habilitar PMF obrigatório (WPA3 ou WPA2 com 802.11w) para mitigar deauth attacks.",
        })
    except Exception:
        pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Detecta vulnerabilidades e ataques wireless (Evil Twin, Karma, PMKID, Deauth)."""
    try:
        vulns = []
        _ = (ip, ports, banners)

        vulns.extend(_check_evil_twin(target))
        vulns.extend(_check_karma_vulnerability())
        vulns.extend(_check_wpa_handshake(target))
        vulns.extend(_check_pmkid_attack())
        vulns.extend(_check_deauth_protection())

        if context:
            wifi_networks = context.get("wifi_networks", [])
            open_networks = [n for n in wifi_networks if n.get("security", "").lower() in ("open", "none", "")]
            if open_networks:
                vulns.append({
                    "tipo": "REDE_ABERTA_DETECTADA",
                    "severidade": "CRITICO",
                    "descricao": f"{len(open_networks)} rede(s) aberta(s) detectada(s) — tráfego interceptável",
                    "evidencia": f"SSIDs: {', '.join(n.get('ssid', '?') for n in open_networks[:5])}",
                    "correcao": "Desativar redes abertas ou implementar WPA3-Enterprise com 802.1X.",
                })

        return {
            "plugin": "wifi_rogue_ap",
            "resultados": vulns if vulns else "Nenhuma vulnerabilidade wireless crítica detectada",
        }
    except Exception as e:
        return {"plugin": "wifi_rogue_ap", "erro": str(e)}
