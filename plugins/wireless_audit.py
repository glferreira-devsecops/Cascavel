# plugins/wireless_audit.py — Cascavel 2026 Intelligence
import socket

import requests

# Wireless management interface ports
WIRELESS_PORTS = [80, 443, 8080, 8443, 22, 23, 161, 162, 53, 67, 68]

# Common wireless AP management paths
AP_PATHS = [
    "/",
    "/login",
    "/admin",
    "/cgi-bin/luci",
    "/cgi-bin/webif",
    "/status",
    "/wireless",
    "/wlan",
    "/wifi",
    "/network/wireless",
    "/goform/wireless",
    "/wireless_basic.htm",
    "/wps_setup.htm",
    "/advwls_top.htm",
    "/wireless_status.htm",
    "/ap_mgmt.htm",
]

# WPS-related paths
WPS_PATHS = [
    "/wps",
    "/wps_setup",
    "/wireless/wps",
    "/wps_pin.htm",
    "/wps_settings",
    "/wps_configure",
    "/wps_server.htm",
]

# Known vulnerable wireless firmware patterns
VULN_FIRMWARE = [
    ("DD-WRT", "3.0-r", "MEDIO"),
    ("OpenWrt", "18.06", "BAIXO"),
    ("Tomato", "1.28", "MEDIO"),
    ("Padavan", "3.4", "BAIXO"),
]

# Rogue AP indicators
ROGUE_INDICATORS = [
    "rogue",
    "evil twin",
    "karma",
    "hostapd",
    "mana",
    "fluxion",
    "airgeddon",
    "wifiphisher",
]


def _check_management_interfaces(target, ports):
    """Check for exposed wireless management interfaces."""
    findings = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            if result == 0:
                proto = "HTTPS" if port in [443, 8443] else "HTTP"
                scheme = "https" if port in [443, 8443] else "http"
                finding = {
                    "tipo": "MGMT_INTERFACE_EXPOSED",
                    "porta": port,
                    "protocolo": proto,
                    "severidade": "ALTO",
                    "descricao": f"Interface de gerenciamento wireless exposta na porta {port}/{proto}",
                    "remediacao": "Desabilitar acesso externo ao gerenciamento do AP. Usar VPN para administração.",
                }
                # Try to identify the AP type
                try:
                    resp = requests.get(f"{scheme}://{target}:{port}/", timeout=5, verify=False)
                    server = resp.headers.get("Server", "")
                    body = resp.text[:2000].lower()
                    if any(kw in body for kw in ["wireless", "wifi", "wlan", "access point", "router"]):
                        finding["descricao"] += " — Interface wireless confirmada"
                        finding["severidade"] = "CRITICO"
                    if server:
                        finding["server"] = server
                except Exception as _exc:
                    pass
                findings.append(finding)
            sock.close()
        except Exception:
            continue
    return findings


def _check_wps_vulnerabilities(target):
    """Check for WPS-related vulnerabilities."""
    findings = []
    scheme = "https" if target.endswith(":443") else "http"
    base = f"{scheme}://{target}"

    for path in WPS_PATHS:
        try:
            resp = requests.get(f"{base}{path}", timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(kw in body for kw in ["wps", "pin", "push button", "pbc"]):
                    finding = {
                        "tipo": "WPS_ENABLED",
                        "path": path,
                        "severidade": "ALTO",
                        "descricao": "WPS detectado — vulnerável a ataques de brute force PIN (Reaver/Bully)",
                        "remediacao": "Desabilitar WPS completamente no AP. Se necessário, usar apenas WPS PBC (push button).",
                    }
                    if "pin" in body and ("enable" in body or "active" in body or "on" in body):
                        finding["severidade"] = "CRITICO"
                        finding["descricao"] = "WPS PIN ativo — brute force trivial em ~4-10 horas"
                    findings.append(finding)
        except Exception:
            continue
    return findings


def _check_weak_encryption(target):
    """Check for weak wireless encryption indicators."""
    findings = []
    scheme = "https" if target.endswith(":443") else "http"
    base = f"{scheme}://{target}"

    # Check management interface for encryption settings
    for path in ["/wireless", "/wireless_basic.htm", "/wlan", "/wifi", "/network/wireless"]:
        try:
            resp = requests.get(f"{base}{path}", timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()

                # WEP detection
                if "wep" in body and any(kw in body for kw in ["enable", "active", "selected", "checked"]):
                    findings.append(
                        {
                            "tipo": "WEP_ENCRYPTION",
                            "path": path,
                            "severidade": "CRITICO",
                            "descricao": "WEP detectado — quebrável em minutos com aircrack-ng",
                            "remediacao": "Migrar imediatamente para WPA3 ou WPA2-AES. WEP é completamente inseguro.",
                        }
                    )

                # WPA1 detection
                if "wpa1" in body or ("wpa" in body and "wpa2" not in body and "wpa3" not in body):
                    if any(kw in body for kw in ["enable", "active", "selected", "checked"]):
                        findings.append(
                            {
                                "tipo": "WPA1_ENCRYPTION",
                                "path": path,
                                "severidade": "ALTO",
                                "descricao": "WPA1 (TKIP) detectado — vulnerável a ataques TKIP e fragmentação",
                                "remediacao": "Migrar para WPA2-AES ou WPA3. WPA1 com TKIP é obsoleto.",
                            }
                        )

                # Open network detection
                if ("open" in body or "none" in body) and "encrypt" in body:
                    if any(kw in body for kw in ["selected", "checked", "active"]):
                        findings.append(
                            {
                                "tipo": "OPEN_NETWORK",
                                "path": path,
                                "severidade": "CRITICO",
                                "descricao": "Rede wireless aberta (sem criptografia) detectada",
                                "remediacao": "Implementar WPA3-Personal ou WPA3-Enterprise mínimo.",
                            }
                        )
        except Exception:
            continue
    return findings


def _check_krack(target):
    """Check for KRACK vulnerability indicators."""
    findings = []
    scheme = "https" if target.endswith(":443") else "http"
    base = f"{scheme}://{target}"

    # Check firmware version for known vulnerable versions
    for path in ["/status", "/about", "/system", "/firmware", "/cgi-bin/status"]:
        try:
            resp = requests.get(f"{base}{path}", timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                # Check for WPA2 without KRACK patch
                if "wpa2" in body:
                    # Look for firmware date indicators
                    for fw_name, fw_version, sev in VULN_FIRMWARE:
                        if fw_version in body or fw_name.lower() in body:
                            findings.append(
                                {
                                    "tipo": "KRACK_POTENTIAL",
                                    "firmware": fw_name,
                                    "versao": fw_version,
                                    "severidade": sev,
                                    "descricao": f"Firmware {fw_name} {fw_version} potencialmente vulnerável ao KRACK (CVE-2017-13077/78/79/80/81/82)",
                                    "remediacao": "Atualizar firmware do AP para versão com patch KRACK. Verificar vendor advisories.",
                                }
                            )
                    # Generic WPA2 without explicit patch
                    if not any(f[0].lower() in body for f in VULN_FIRMWARE):
                        findings.append(
                            {
                                "tipo": "WPA2_KRACK_CHECK",
                                "severidade": "MEDIO",
                                "descricao": "WPA2 detectado — verificar se firmware está patchado contra KRACK",
                                "remediacao": "Confirmar que firmware está atualizado. Testar com ferramenta KRACK dedicada.",
                            }
                        )
        except Exception:
            continue
    return findings


def _check_rogue_ap(target):
    """Check for rogue AP indicators on management interface."""
    findings = []
    scheme = "https" if target.endswith(":443") else "http"
    base = f"{scheme}://{target}"

    try:
        resp = requests.get(f"{base}/", timeout=5, verify=False)
        if resp.status_code == 200:
            body = resp.text.lower()
            server = resp.headers.get("Server", "").lower()

            # Check for rogue AP tool indicators
            for indicator in ROGUE_INDICATORS:
                if indicator in body or indicator in server:
                    findings.append(
                        {
                            "tipo": "ROGUE_AP_INDICATOR",
                            "indicador": indicator,
                            "severidade": "CRITICO",
                            "descricao": f"Indicador de rogue AP detectado: '{indicator}' — possível evil twin",
                            "remediacao": "Investigar imediatamente. Implementar WIDS/WIPS para detecção de APs não autorizados.",
                        }
                    )

            # Check for multiple SSIDs (potential evil twin setup)
            if body.count("ssid") > 3:
                findings.append(
                    {
                        "tipo": "MULTIPLE_SSIDS",
                        "severidade": "ALTO",
                        "descricao": "Múltiplos SSIDs configurados — verificar se são legítimos",
                        "remediacao": "Auditar SSIDs configurados. Remover não autorizados.",
                    }
                )

            # Check for hostapd configuration exposure
            if "hostapd" in body:
                findings.append(
                    {
                        "tipo": "HOSTAPD_EXPOSED",
                        "severidade": "ALTO",
                        "descricao": "Configuração hostapd exposta — possível AP rogue ou config indevida",
                        "remediacao": "Restringir acesso à interface de gerenciamento. Verificar legitimidade do AP.",
                    }
                )
    except Exception as _exc:
        pass
    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    Wireless Audit 2026-Grade — Management Interfaces, WPS, Encryption, KRACK, Rogue AP.

    Técnicas: exposed management interfaces, WPS brute force indicators,
    WEP/WPA1/open network detection, KRACK vulnerability fingerprinting,
    rogue AP / evil twin detection, multiple SSID auditing.
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "management_interfaces": [],
        "wps_vulnerabilities": [],
        "weak_encryption": [],
        "krack_indicators": [],
        "rogue_ap_indicators": [],
    }

    # Determine target (strip scheme if present)
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Check for management interfaces
    resultado["management_interfaces"] = _check_management_interfaces(clean_target, WIRELESS_PORTS)

    # Check WPS vulnerabilities
    resultado["wps_vulnerabilities"] = _check_wps_vulnerabilities(clean_target)

    # Check weak encryption
    resultado["weak_encryption"] = _check_weak_encryption(clean_target)

    # Check KRACK vulnerability
    resultado["krack_indicators"] = _check_krack(clean_target)

    # Check rogue AP indicators
    resultado["rogue_ap_indicators"] = _check_rogue_ap(clean_target)

    # Summary
    total_findings = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )

    resultado["resumo"] = {
        "total_achados": total_findings,
        "criticos": critico,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total_findings > 0 else "LIMPO"),
    }

    return {
        "plugin": "wireless_audit",
        "versao": "2026.1",
        "tecnicas": [
            "mgmt_interface_scan",
            "wps_detection",
            "weak_encryption_check",
            "krack_fingerprint",
            "rogue_ap_detection",
        ],
        "resultados": resultado,
    }
