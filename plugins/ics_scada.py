"""
[+] Plugin: ICS/SCADA Security Testing
[+] Description: Testa interfaces Modbus, DNP3, BACnet, Siemens S7 e OPC UA expostas
[+] Category: Industrial Control Systems
[+] CVSS: 9.0 (Critical)
[+] Author: CASCAVEL Framework
"""

import socket
import struct
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ICS/SCADA protocol ports
ICS_PORTS = {
    502: "Modbus TCP",
    20000: "DNP3",
    47808: "BACnet",
    47809: "BACnet UDP",
    102: "Siemens S7 (ISO-TSAP)",
    4840: "OPC UA",
    4841: "OPC UA (alt)",
    4842: "OPC UA (alt)",
    789: "Red Lion Controls",
    10001: "Siemens S7-200",
    5007: "Mitsubishi MELSEC",
    5020: "Schneider Modicon",
    9600: "OMRON FINS",
    2222: "EtherNet/IP",
    44818: "EtherNet/IP (CIP)",
}


def _check_modbus(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica interfaces Modbus TCP expostas e sem autenticação."""
    findings = []
    if 502 not in ports:
        return findings

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 502))

        # Build Modbus "Report Slave ID" request (function 0x11)
        # Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function Code (1)
        modbus_request = struct.pack(">HHHBB", 0x0001, 0x0000, 0x0006, 0xFF, 0x11)
        sock.send(modbus_request)

        response = sock.recv(256)
        sock.close()

        if len(response) > 8:
            # Valid Modbus response
            function_code = response[7] if len(response) > 7 else 0
            if function_code == 0x11:
                slave_id = response[8:].decode("utf-8", errors="ignore")
                findings.append({
                    "tipo": "MODBUS_SEM_AUTENTICACAO",
                    "severidade": "CRITICO",
                    "descricao": "Modbus TCP exposto sem autenticação — controle total de dispositivos industriais",
                    "evidencia": f"Slave ID: {slave_id[:100]}",
                    "correcao": "Implementar Modbus Security (TLS). Restringir acesso via firewall industrial.",
                })
            elif function_code & 0x80:
                # Exception response — still indicates service is active
                findings.append({
                    "tipo": "MODBUS_ATIVO",
                    "severidade": "ALTO",
                    "descricao": "Modbus TCP ativo na porta 502 — responder a requisições",
                    "evidencia": f"Response: {response.hex()[:60]}",
                    "correcao": "Restringir acesso Modbus a rede OT isolada.",
                })
            else:
                findings.append({
                    "tipo": "MODBUS_RESPOSTA",
                    "severidade": "ALTO",
                    "descricao": "Modbus TCP respondeu na porta 502 — serviço industrial exposto",
                    "evidencia": f"Response hex: {response.hex()[:80]}",
                    "correcao": "Segmentar rede OT/IT. Implementar firewall industrial entre zonas.",
                })
    except (TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    return findings


def _check_dnp3(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades em DNP3 (Distributed Network Protocol)."""
    findings = []
    if 20000 not in ports:
        return findings

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 20000))

        # DNP3 Link Layer frame — request for device attributes
        # Start (0x05 0x64) + Length (5) + Control (0xC4) + Destination (0x00) + Source (0x01) + CRC
        dnp3_request = bytes([0x05, 0x64, 0x05, 0xC4, 0x00, 0x01])
        # Calculate CRC16 (simplified — DNP3 uses CRC-16/DNP)
        sock.send(dnp3_request)

        response = sock.recv(512)
        sock.close()

        if len(response) > 5:
            # Check for DNP3 response start bytes
            if response[0] == 0x05 and response[1] == 0x64:
                findings.append({
                    "tipo": "DNP3_SEM_AUTENTICACAO",
                    "severidade": "CRITICO",
                    "descricao": "DNP3 exposto sem autenticação — acesso a sistemas SCADA/energia",
                    "evidencia": f"Response: {response.hex()[:80]}",
                    "correcao": "Implementar DNP3 Secure Authentication (SAv5). Isolar rede DNP3.",
                })
            else:
                findings.append({
                    "tipo": "DNP3_ATIVO",
                    "severidade": "ALTO",
                    "descricao": "DNP3 respondeu na porta 20000 — protocolo industrial exposto",
                    "correcao": "Restringir acesso DNP3 via firewall industrial.",
                })
    except (TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    return findings


def _check_bacnet(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica configurações incorretas em BACnet (Building Automation)."""
    findings = []
    if 47808 not in ports and 47809 not in ports:
        return findings

    port = 47808 if 47808 in ports else 47809
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # BACnet "Who-Is" broadcast (Who-Is service request)
        # BVLC type (0x81) + Function (0x0B) + Length (0x0008) + NPDU + Who-Is
        bacnet_whois = bytes([
            0x81, 0x0B, 0x00, 0x08,  # BVLC header
            0x01, 0x00,              # NPDU version + control
            0x10, 0x08               # Unconfirmed Who-Is
        ])
        sock.sendto(bacnet_whois, (ip, port))

        response, addr = sock.recvfrom(512)
        sock.close()

        if len(response) > 4:
            # Parse BACnet I-Am response
            findings.append({
                "tipo": "BACNET_SEM_AUTENTICACAO",
                "severidade": "ALTO",
                "descricao": "BACnet respondeu a Who-Is sem autenticação — edifício/sistema de automação acessível",
                "evidencia": f"Response: {response.hex()[:80]}",
                "correcao": "Implementar BACnet/SC (Secure Connect). Restringir broadcast em rede.",
            })

            # Check for BACnet device enumeration
            if response[1] == 0x00:  # I-Am response
                findings.append({
                    "tipo": "BACNET_ENUMERACAO",
                    "severidade": "MEDIO",
                    "descricao": "Dispositivo BACnet enumerável — informações de device expostas",
                    "correcao": "Desabilitar Who-Is responses em dispositivos não necessários.",
                })
    except (TimeoutError, OSError):
        pass
    except Exception:
        pass
    return findings


def _check_siemens_s7(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades Siemens S7 (ISO-TSAP)."""
    findings = []
    if 102 not in ports:
        return findings

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 102))

        # ISO-TSAP Connection Request (COTP)
        # TPKT header + COTP CR
        iso_cr = bytes([
            0x03, 0x00, 0x00, 0x16,  # TPKT: version=3, length=22
            0x11, 0xE0, 0x00, 0x00,  # COTP: length=17, CR (0xE0)
            0x00, 0x01, 0x00, 0x01,  # DST/Source ref
            0x00, 0xC1, 0x02, 0x01, 0x00,  # Parameter: calling TSAP
            0xC2, 0x02, 0x01, 0x02,  # Parameter: called TSAP
            0xC0, 0x01, 0x09         # Parameter: TPDU size
        ])
        sock.send(iso_cr)

        response = sock.recv(256)
        sock.close()

        if len(response) >= 6:
            if response[5] == 0xD0:  # Connection Confirm
                findings.append({
                    "tipo": "S7_SEM_AUTENTICACAO",
                    "severidade": "CRITICO",
                    "descricao": "Siemens S7 aceita conexões ISO-TSAP sem autenticação — controle de PLC/SCADA",
                    "evidencia": f"Response: {response.hex()[:60]}",
                    "correcao": "Habilitar S7 Communication Security. Usar CP 443-1 com TLS. Restringir acesso via firewall.",
                })

                # Try to get PLC info via S7 Get PLC Info
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(5)
                    sock2.connect((ip, 102))
                    sock2.send(iso_cr)
                    sock2.recv(256)  # Connection confirm

                    # S7 Setup communication
                    s7_setup = bytes([
                        0x03, 0x00, 0x00, 0x19,
                        0x02, 0xF0, 0x80,       # COTP DT
                        0x32, 0x01, 0x00, 0x00,  # S7 header
                        0x00, 0x00, 0x00, 0x08,  # PDU size
                        0x00, 0x00,
                        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0  # Setup
                    ])
                    sock2.send(s7_setup)
                    setup_resp = sock2.recv(256)
                    sock2.close()

                    if len(setup_resp) > 10:
                        findings.append({
                            "tipo": "S7_PDU_NEGOTIADO",
                            "severidade": "ALTO",
                            "descricao": "S7 PDU negociado com sucesso — protocolo industrial exposto",
                            "correcao": "Implementar S7 TLS (porta 102 com CP). Isolar rede OT.",
                        })
                except Exception:
                    pass
    except (TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    return findings


def _check_opcua(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Verifica segurança OPC UA (Open Platform Communications Unified Architecture)."""
    findings = []
    if not HAS_REQUESTS:
        return findings

    opcua_ports = [p for p in [4840, 4841, 4842] if p in ports]
    for port in opcua_ports:
        base_url = f"http://{ip}:{port}"

        try:
            # Check OPC UA Discovery endpoint
            discovery_url = f"{base_url}/discovery"
            resp = requests.get(discovery_url, timeout=5, verify=False)
            if resp.status_code == 200:
                findings.append({
                    "tipo": "OPCUA_DISCOVERY_EXPOSTO",
                    "severidade": "ALTO",
                    "descricao": f"OPC UA Discovery endpoint exposto na porta {port}",
                    "evidencia": f"Response: {resp.text[:200]}",
                    "correcao": "Desabilitar discovery endpoint em produção. Usar OPC UA com TLS.",
                })

            # Check for anonymous access
            endpoint_url = f"{base_url}/discovery/endpoints"
            resp = requests.get(endpoint_url, timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                if "anonymous" in body:
                    findings.append({
                        "tipo": "OPCUA_ANONYMOUS_ACCESS",
                        "severidade": "CRITICO",
                        "descricao": "OPC UA permite acesso anônimo — controle de sistema industrial sem autenticação",
                        "correcao": "Desabilitar anonymous access no OPC UA server. Exigir certificados X.509.",
                    })
                if "securitymode" in body and "none" in body:
                    findings.append({
                        "tipo": "OPCUA_SEM_SEGURANCA",
                        "severidade": "CRITICO",
                        "descricao": "OPC UA com SecurityMode=None — comunicação sem criptografia",
                        "correcao": "Configurar SecurityMode=SignAndEncrypt. Nunca usar None em produção.",
                    })
        except Exception:
            pass

        # Check raw socket for Binary TCP protocol
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            # OPC UA Hello message header
            hello = bytes([
                0x4F, 0x50, 0x4E, 0x46,  # "OPNF" (OPC UA header)
                0x00, 0x00, 0x00, 0x00,  # Message size (placeholder)
            ])
            sock.send(hello)
            response = sock.recv(256)
            sock.close()
            if len(response) > 4:
                findings.append({
                    "tipo": "OPCUA_BINARY_EXPOSTO",
                    "severidade": "ALTO",
                    "descricao": f"OPC UA Binary TCP ativo na porta {port}",
                    "correcao": "Restringir acesso OPC UA via rede OT isolada.",
                })
        except (TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Auditoria de segurança ICS/SCADA — Modbus, DNP3, BACnet, Siemens S7, OPC UA."""
    try:
        vulns = []
        vulns.extend(_check_modbus(ip, ports))
        vulns.extend(_check_dnp3(ip, ports))
        vulns.extend(_check_bacnet(ip, ports))
        vulns.extend(_check_siemens_s7(ip, ports))
        vulns.extend(_check_opcua(ip, ports))

        if context:
            ot_network = context.get("ot_network", False)
            if ot_network:
                vulns.append({
                    "tipo": "OT_NETWORK_CONTEXT",
                    "severidade": "INFO",
                    "descricao": "Rede OT identificada via contexto — verificar segmentação IT/OT",
                    "correcao": "Implementar Purdue Model de segmentação. Usar firewall industrial.",
                })

        return {
            "plugin": "ics_scada",
            "resultados": vulns if vulns else "Nenhuma vulnerabilidade ICS/SCADA detectada",
        }
    except Exception as e:
        return {"plugin": "ics_scada", "erro": str(e)}
