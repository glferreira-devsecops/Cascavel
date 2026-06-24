"""
[+] Plugin: Firmware Emulation Testing
[+] Description: Testa interfaces de emulação expostas, QEMU escapes, debug interfaces e bypass de assinatura
[+] Category: Firmware / Embedded Security
[+] CVSS: 7.5 (High)
[+] Author: CASCAVEL Framework
"""

import re
import socket
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Common emulation/QEMU ports
EMULATION_PORTS = {
    5900: "VNC (QEMU/KVM display)",
    5901: "VNC Display :1",
    5902: "VNC Display :2",
    5930: "QEMU Monitor (HMP)",
    4444: "QEMU GDB stub",
    1234: "QEMU user-mode",
    2222: "QEMU SSH forwarding",
    9090: "QEMU QMP (JSON Monitor)",
    8080: "Firmware web interface",
    80: "Firmware web interface (HTTP)",
    443: "Firmware web interface (HTTPS)",
}

# Known firmware debug paths
DEBUG_PATHS = [
    "/cgi-bin/luci",         # OpenWrt
    "/cgi-bin/admin",        # Generic router
    "/cgi-bin/debug",        # Debug interface
    "/debug", "/diag", "/shell", "/cli",
    "/system/debug", "/admin/debug",
    "/firmware", "/upgrade", "/flash",
    "/api/v1/system/debug",
    "/api/v1/firmware",
]


def _check_emulation_interfaces(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica interfaces de emulação expostas na rede."""
    findings = []
    for port, desc in EMULATION_PORTS.items():
        if port not in ports:
            continue
        # Try to connect and grab banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = ""
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(512).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                sock.close()

                # Check for QEMU-specific banners
                if any(kw in banner.lower() for kw in ["qemu", "kvm", "vnc", "monitor"]):
                    findings.append({
                        "tipo": "QEMU_INTERFACE_EXPOSTA",
                        "severidade": "CRITICO",
                        "descricao": f"Interface QEMU/KVM exposta na porta {port} ({desc})",
                        "evidencia": f"Banner: {banner[:200]}",
                        "correcao": "Restringir acesso via firewall. Nunca expor interfaces de emulação em rede pública.",
                    })
                elif port in [5900, 5901, 5902]:
                    findings.append({
                        "tipo": "VNC_EMULACAO_EXPOSTO",
                        "severidade": "ALTO",
                        "descricao": f"VNC (possível emulação) exposto na porta {port}",
                        "evidencia": f"Banner: {banner[:100]}" if banner else "Conexão aceita",
                        "correcao": "Autenticar VNC com senha forte e restringir via firewall.",
                    })
                elif port == 9090:
                    findings.append({
                        "tipo": "QMP_EXPOSTO",
                        "severidade": "CRITICO",
                        "descricao": f"QEMU Monitor Protocol (QMP) exposto na porta {port} — controle total da VM",
                        "correcao": "Desabilitar QMP remoto ou restringir via socket Unix local.",
                    })
        except (TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
    return findings


def _check_qemu_escape(target: str, ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades conhecidas de escape do QEMU."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    # Check QMP for version info (escape CVEs are version-specific)
    if 9090 in ports:
        try:
            resp = requests.get(f"http://{ip}:9090", timeout=5)
            if resp.status_code == 200:
                data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                version = data.get("QMP", {}).get("version", {}).get("qemu", {}).get("micro", "unknown")
                findings.append({
                    "tipo": "QEMU_VERSION_EXPOSTA",
                    "severidade": "ALTO",
                    "descricao": f"Versão do QEMU exposta via QMP: {version}",
                    "evidencia": str(data)[:200],
                    "correcao": "Verificar CVEs para a versão. Atualizar para última versão estável.",
                })
        except Exception:
            pass

    # Check for known QEMU escape CVEs via VNC
    vnc_ports = [p for p in [5900, 5901, 5902] if p in ports]
    for port in vnc_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            # VNC handshake — read server version
            banner = sock.recv(256).decode("utf-8", errors="ignore")
            sock.close()

            if "RFB" in banner:
                version_match = re.search(r"RFB (\d+\.\d+)", banner)
                if version_match:
                    vnc_ver = version_match.group(1)
                    # Old VNC versions have known exploits
                    if vnc_ver in ["3.3", "3.7", "3.8"]:
                        findings.append({
                            "tipo": "VNC_VERSAO_ANTIGA",
                            "severidade": "ALTO",
                            "descricao": f"VNC versão {vnc_ver} — vulnerabilidades conhecidas de escape",
                            "evidencia": f"Banner: {banner[:100]}",
                            "correcao": "Atualizar VNC e QEMU. Usar TLS e autenticação forte.",
                        })
        except Exception:
            pass
    return findings


def _check_debug_interfaces(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica interfaces de debug de firmware expostas."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    web_ports = [p for p in [80, 443, 8080, 8443, 8000] if p in ports]
    for port in web_ports:
        scheme = "https" if port in [443, 8443] else "http"
        base = f"{scheme}://{ip}:{port}"
        for path in DEBUG_PATHS:
            try:
                resp = requests.get(f"{base}{path}", timeout=3, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(kw in body for kw in ["debug", "diagnostic", "shell", "console", "firmware", "flash"]):
                        findings.append({
                            "tipo": "DEBUG_INTERFACE_EXPOSTA",
                            "severidade": "ALTO",
                            "descricao": f"Interface de debug em {path} (porta {port})",
                            "evidencia": f"HTTP {resp.status_code}, body: {resp.text[:150]}",
                            "correcao": "Desabilitar interfaces de debug em produção. Usar acesso restrito via VPN.",
                        })
            except Exception:
                continue

    # Check for JTAG/SWD debug ports (common in embedded)
    jtag_ports = {3333: "OpenOCD", 4444: "Telnet debug", 2333: "J-Link GDB"}
    for port, desc in jtag_ports.items():
        if port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                banner = sock.recv(256).decode("utf-8", errors="ignore")
                sock.close()
                findings.append({
                    "tipo": "JTAG_DEBUG_EXPOSTO",
                    "severidade": "CRITICO",
                    "descricao": f"Interface de debug {desc} exposta na porta {port}",
                    "evidencia": f"Banner: {banner[:100]}" if banner else "Conexão aceita",
                    "correcao": "Desabilitar JTAG/SWD em produção. Usar efuse ou lock bits para proteção.",
                })
            except Exception:
                pass
    return findings


def _check_firmware_signing(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica se o firmware suporta/valida assinatura de atualizações."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    web_ports = [p for p in [80, 443, 8080, 8443] if p in ports]
    for port in web_ports:
        scheme = "https" if port in [443, 8443] else "http"
        base = f"{scheme}://{ip}:{port}"
        try:
            # Check for firmware upgrade endpoints
            upgrade_paths = ["/cgi-bin/upgrade", "/firmware/upgrade", "/api/firmware/update", "/admin/upgrade"]
            for path in upgrade_paths:
                try:
                    resp = requests.get(f"{base}{path}", timeout=3, verify=False)
                    if resp.status_code == 200 and "upload" in resp.text.lower():
                        # Check if there's signature validation
                        has_sign = any(kw in resp.text.lower() for kw in ["signature", "sign", "verify", "checksum", "hash"])
                        if not has_sign:
                            findings.append({
                                "tipo": "FIRMWARE_SEM_ASSINATURA",
                                "severidade": "ALTO",
                                "descricao": f"Endpoint de upgrade em {path} sem indicação de validação de assinatura",
                                "correcao": "Implementar verificação de assinatura digital em atualizações de firmware.",
                            })
                except Exception:
                    continue
        except Exception:
            pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Testa segurança de emulação de firmware — interfaces expostas, QEMU escapes, debug e assinatura."""
    try:
        vulns = []
        vulns.extend(_check_emulation_interfaces(ip, ports))
        vulns.extend(_check_qemu_escape(target, ip, ports))
        vulns.extend(_check_debug_interfaces(ip, ports))
        vulns.extend(_check_firmware_signing(ip, ports))

        if context:
            device_info = context.get("device_info", {})
            if device_info.get("embedded"):
                vulns.append({
                    "tipo": "DISPOSITIVO_EMBARCADO",
                    "severidade": "INFO",
                    "descricao": "Dispositivo embarcado detectado via contexto — verificar firmware atualizado",
                    "correcao": "Manter firmware atualizado e desabilitar interfaces não utilizadas.",
                })

        return {
            "plugin": "firmware_emulation",
            "resultados": vulns if vulns else "Nenhuma vulnerabilidade de emulação de firmware detectada",
        }
    except Exception as e:
        return {"plugin": "firmware_emulation", "erro": str(e)}
