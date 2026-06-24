"""
[+] Plugin: Bluetooth Security Audit
[+] Description: Testa serviços Bluetooth expostos, BlueBorne, BLE misconfig, replay e KNOB
[+] Category: Wireless / Bluetooth Security
[+] CVSS: 7.0 (High)
[+] Author: CASCAVEL Framework
"""

import re
import shutil
import subprocess
from typing import Any


def _check_bluetooth_adapter() -> dict[str, Any] | None:
    """Verifica se há adaptador Bluetooth disponível."""
    if shutil.which("hciconfig"):
        try:
            result = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=10)
            if "hci" in result.stdout.lower():
                return {"available": True, "tool": "hciconfig", "output": result.stdout[:500]}
        except Exception:
            pass
    if shutil.which("bluetoothctl"):
        try:
            result = subprocess.run(["bluetoothctl", "show"], capture_output=True, text=True, timeout=10)
            if "controller" in result.stdout.lower():
                return {"available": True, "tool": "bluetoothctl", "output": result.stdout[:500]}
        except Exception:
            pass
    return None


def _check_bluetooth_services(target: str) -> list[dict[str, Any]]:
    """Verifica serviços Bluetooth expostos via SDP."""
    findings = []
    if not shutil.which("sdptool"):
        return findings

    try:
        # Browse SDP records of target
        result = subprocess.run(["sdptool", "browse", target], capture_output=True, text=True, timeout=15)
        output = result.stdout
        if not output and result.returncode != 0:
            return findings

        # Parse dangerous service classes
        dangerous_services = {
            "OBEX Object Push": "ALTO",
            "OBEX File Transfer": "CRITICO",
            "Dialup Networking": "ALTO",
            "Serial Port": "ALTO",
            "Audio Source": "MEDIO",
            "AudioSink": "MEDIO",
            "Handsfree": "MEDIO",
            "Network Access Point": "ALTO",
            "PAN": "ALTO",
        }

        for service, severity in dangerous_services.items():
            if service.lower() in output.lower():
                findings.append(
                    {
                        "tipo": "BT_SERVICE_EXPOSTO",
                        "severidade": severity,
                        "descricao": f"Serviço Bluetooth '{service}' exposto via SDP",
                        "evidencia": output[:200],
                        "correcao": f"Desabilitar o serviço '{service}' se não necessário. Usar whitelist de dispositivos.",
                    }
                )
    except Exception:
        pass
    return findings


def _check_blueborne(target: str) -> list[dict[str, Any]]:
    """Verifica vulnerabilidade a ataques BlueBorne (CVE-2017-0781 a CVE-2017-1000251)."""
    findings = []
    if not shutil.which("hcitool"):
        return findings

    try:
        # Get device info via hcitool
        result = subprocess.run(["hcitool", "info", target], capture_output=True, text=True, timeout=10)
        output = result.stdout

        # Check LMP version — older versions are more vulnerable
        lmp_match = re.search(r"LMP Version:\s*(\d+)", output)
        if lmp_match:
            lmp_ver = int(lmp_match.group(1))
            # LMP 0-8 = Bluetooth 1.0 - 4.0 (vulnerable to most BlueBorne)
            if lmp_ver <= 8:
                findings.append(
                    {
                        "tipo": "BLUEBORNE_VULNERAVEL",
                        "severidade": "CRITICO",
                        "descricao": f"LMP versão {lmp_ver} — vulnerável a ataques BlueBorne",
                        "evidencia": output[:200],
                        "correcao": "Atualizar firmware do dispositivo Bluetooth. Desabilitar Bluetooth quando não utilizado.",
                    }
                )
            elif lmp_ver <= 10:
                findings.append(
                    {
                        "tipo": "BLUEBORNE_PARCIAL",
                        "severidade": "MEDIO",
                        "descricao": f"LMP versão {lmp_ver} — parcialmente vulnerável a BlueBorne",
                        "correcao": "Verificar patches de segurança do dispositivo.",
                    }
                )

        # Check if Bluetooth is discoverable (increases attack surface)
        if "discoverable" in output.lower() or "scan mode: discoverable" in output.lower():
            findings.append(
                {
                    "tipo": "BT_DISCOVERABLE",
                    "severidade": "ALTO",
                    "descricao": "Bluetooth em modo discoverable — aumenta superfície de ataque",
                    "correcao": "Desabilitar modo discoverable. Usar pairing manual.",
                }
            )
    except Exception:
        pass
    return findings


def _check_ble_misconfig(target: str) -> list[dict[str, Any]]:
    """Verifica configurações incorretas em BLE (Bluetooth Low Energy)."""
    findings = []
    if not shutil.which("hcitool"):
        return findings

    try:
        # Scan for BLE devices
        result = subprocess.run(["hcitool", "lescan", "--duplicates"], capture_output=True, text=True, timeout=10)
        output = result.stdout

        # Check for BLE devices without privacy (static MAC)
        if target.upper() in output or target.lower() in output:
            # Static public address in BLE = no privacy
            findings.append(
                {
                    "tipo": "BLE_SEM_PRIVACIDADE",
                    "severidade": "MEDIO",
                    "descricao": "Dispositivo BLE com endereço estático — rastreável",
                    "correcao": "Habilitar Resolvable Private Address (RPA) no dispositivo BLE.",
                }
            )
    except Exception:
        pass

    # Check for BLE GATT services exposed
    if shutil.which("gatttool"):
        try:
            result = subprocess.run(
                ["gatttool", "-b", target, "--characteristics"], capture_output=True, text=True, timeout=10
            )
            if "characteristics" in result.stdout.lower():
                # Check for writable characteristics (potential attack vector)
                writable_chars = re.findall(r"char props = 0x0[26a]", result.stdout)
                if writable_chars:
                    findings.append(
                        {
                            "tipo": "BLE_GATT_GRAVAVEL",
                            "severidade": "ALTO",
                            "descricao": "Características BLE GATT graváveis detectadas — possível manipulação",
                            "evidencia": result.stdout[:200],
                            "correcao": "Implementar autenticação BLE para características graváveis.",
                        }
                    )
        except Exception:
            pass
    return findings


def _check_replay_attack() -> list[dict[str, Any]]:
    """Verifica vulnerabilidade a ataques de replay em Bluetooth."""
    findings = []
    # Check if Bluetooth uses legacy pairing (vulnerable to replay)
    if shutil.which("btmgmt"):
        try:
            result = subprocess.run(["btmgmt", "info"], capture_output=True, text=True, timeout=10)
            output = result.stdout
            # Check for Secure Connections support
            if "secure-conn" not in output.lower() or "supported" not in output.lower():
                findings.append(
                    {
                        "tipo": "BT_LEGACY_PAIRING",
                        "severidade": "ALTO",
                        "descricao": "Bluetooth sem Secure Connections — vulnerável a replay attacks no pairing",
                        "correcao": "Habilitar Secure Connections (Bluetooth 4.2+). Desabilitar legacy pairing.",
                    }
                )
            # Check for SSP (Secure Simple Pairing)
            if "ssp" not in output.lower():
                findings.append(
                    {
                        "tipo": "BT_SEM_SSP",
                        "severidade": "MEDIO",
                        "descricao": "Secure Simple Pairing (SSP) não detectado",
                        "correcao": "Habilitar SSP para proteção contra MITM durante pareamento.",
                    }
                )
        except Exception:
            pass
    return findings


def _check_knob_vulnerability(target: str) -> list[dict[str, Any]]:
    """Verifica vulnerabilidade KNOB (CVE-2019-9506) — negociação de encryption key curta."""
    findings = []
    if not shutil.which("hcitool"):
        return findings

    try:
        result = subprocess.run(["hcitool", "info", target], capture_output=True, text=True, timeout=10)
        output = result.stdout

        # KNOB attack targets encryption key negotiation
        # Devices with LMP < 9 (pre-Bluetooth 5.0) are more susceptible
        lmp_match = re.search(r"LMP Version:\s*(\d+)", output)
        if lmp_match:
            lmp_ver = int(lmp_match.group(1))
            if lmp_ver < 9:
                findings.append(
                    {
                        "tipo": "KNOB_VULNERAVEL",
                        "severidade": "ALTO",
                        "descricao": f"LMP versão {lmp_ver} — vulnerável ao ataque KNOB (encryption key negotiation)",
                        "correcao": "Atualizar firmware. Desabilitar Bluetooth quando não utilizado. Monitorar downgrade de encryption.",
                    }
                )

        # Check features for encryption key size
        features_match = re.search(r"Features:\s*(0x[0-9a-fA-F]+)", output)
        if features_match:
            features = features_match.group(1)
            findings.append(
                {
                    "tipo": "KNOB_FEATURES",
                    "severidade": "INFO",
                    "descricao": f"Features Bluetooth: {features} — verificar suporte a encryption key negotiation",
                    "correcao": "Verificar se o dispositivo suporta encryption key size mínimo de 16 bytes.",
                }
            )
    except Exception:
        pass
    return findings


def run(
    target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None
) -> dict[str, Any] | None:
    """Auditoria de segurança Bluetooth — serviços expostos, BlueBorne, BLE, replay, KNOB."""
    try:
        vulns = []
        _ = (ip, ports, banners)

        # Try to resolve target as Bluetooth address
        bt_target = target
        if context and context.get("bluetooth_address"):
            bt_target = context["bluetooth_address"]

        adapter = _check_bluetooth_adapter()
        if not adapter:
            vulns.append(
                {
                    "tipo": "BT_ADAPTER_INDISPONIVEL",
                    "severidade": "INFO",
                    "descricao": "Adaptador Bluetooth não detectado — auditoria limitada",
                    "correcao": "Executar em host com adaptador Bluetooth para auditoria completa.",
                }
            )
            return {
                "plugin": "bluetooth_audit",
                "resultados": vulns,
            }

        vulns.extend(_check_bluetooth_services(bt_target))
        vulns.extend(_check_blueborne(bt_target))
        vulns.extend(_check_ble_misconfig(bt_target))
        vulns.extend(_check_replay_attack())
        vulns.extend(_check_knob_vulnerability(bt_target))

        return {
            "plugin": "bluetooth_audit",
            "resultados": vulns if vulns else "Nenhuma vulnerabilidade Bluetooth crítica detectada",
        }
    except Exception as e:
        return {"plugin": "bluetooth_audit", "erro": str(e)}
