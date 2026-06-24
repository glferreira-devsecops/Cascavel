# plugins/ad_detection.py — Cascavel 2026 Intelligence
import re
import shlex
import shutil
import subprocess

import requests

# ──────────── AD ENUMERATION TOOLS ────────────
TOOLS = {
    "smbclient": "smbclient",
    "rpcclient": "rpcclient",
    "ldapsearch": "ldapsearch",
    "nmap": "nmap",
    "enum4linux": "enum4linux",
    "enum4linux-ng": "enum4linux-ng",
    "crackmapexec": "crackmapexec",
    "impacket-GetUserSPNs": "impacket-GetUserSPNs",
    "impacket-GetNPUsers": "impacket-GetNPUsers",
    "impacket-findDelegation": "impacket-findDelegation",
    "Responder": "Responder",
}

# ──────────── SMB NULL SESSION CHECKS ────────────
SMB_SHARES_TO_CHECK = [
    "IPC$", "C$", "ADMIN$", "NETLOGON", "SYSVOL",
    "print$", "shares", "public", "common", "shared",
]

# ──────────── COMMON LDAP BASE DNs ────────────
COMMON_BASE_DNS = [
    "",  # Root DSE
]


def run(target, ip, ports, banners, context=None):
    """
    Scanner Active Directory 2026-Grade — SMB Enumeration, LDAP Enumeration,
    Kerberos User Enum, AD Misconfigurations, Unconstrained Delegation,
    LLMNR/NBT-NS Poisoning.

    Técnicas: SMB null session (shares/domain/users), LDAP anonymous bind
    (root DSE/base DN enumeration), Kerberos pre-auth (AS-REP roasting),
    common AD misconfigs (SMB signing, LLMNR, NBT-NS, mDNS, WPAD),
    unconstrained delegation detection, SPN enumeration, DNS resolution.
    """
    _ = (ip, ports, banners)
    vulns = []

    # Detect available tools
    available_tools = _detect_tools()

    # SMB Enumeration
    vulns.extend(_enum_smb(target, available_tools))

    # LDAP Enumeration
    vulns.extend(_enum_ldap(target, available_tools))

    # Kerberos Enumeration
    vulns.extend(_enum_kerberos(target, available_tools))

    # AD Misconfigurations
    vulns.extend(_check_ad_misconfigs(target, available_tools))

    # Unconstrained Delegation
    vulns.extend(_check_unconstrained_delegation(target, available_tools))

    # LLMNR/NBT-NS Poisoning
    vulns.extend(_check_poisoning_opportunities(target))

    # Network-level AD checks
    vulns.extend(_network_ad_checks(target))

    return {
        "plugin": "ad_detection",
        "versao": "2026.1",
        "tecnicas": [
            "smb_null_session",
            "ldap_anonymous_bind",
            "kerberos_user_enum",
            "ad_misconfigurations",
            "unconstrained_delegation",
            "llmnr_nbtns_poisoning",
            "smb_signing",
            "spn_enumeration",
        ],
        "ferramentas_disponiveis": available_tools,
        "resultados": vulns if vulns else "Nenhuma detecção AD encontrada",
    }


def _detect_tools():
    """Detecta ferramentas de enumeration AD disponíveis."""
    available = {}
    for name, cmd in TOOLS.items():
        if shutil.which(cmd):
            available[name] = True
    return available


def _run_cmd(cmd, timeout=30):
    """Executa comando com timeout e retorna stdout."""
    try:
        proc = subprocess.run(
            cmd, shell=False, capture_output=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def _enum_smb(target, tools):
    """Enumera SMB — null sessions, shares, domínio, usuários."""
    vulns = []
    safe = shlex.quote(target)

    # SMB client — null session share listing
    if tools.get("smbclient"):
        stdout, stderr, rc = _run_cmd(
            ["smbclient", "-L", f"//{safe}", "-N", "--no-pass"]
        )
        if rc == 0 and stdout:
            shares = re.findall(r"^\s*([A-Za-z0-9\$\-_.]+)\s+Disk", stdout, re.MULTILINE)
            ipc_shares = re.findall(r"^\s*([A-Za-z0-9\$\-_.]+)\s+IPC", stdout, re.MULTILINE)

            if shares:
                vulns.append({
                    "tipo": "SMB_NULL_SESSION_SHARES",
                    "shares": shares,
                    "severidade": "ALTO",
                    "descricao": f"SMB null session aceita — {len(shares)} shares listados!",
                    "remediao": "Desabilitar null sessions. Configurar restrictanonymous=2.",
                })

                # Try to connect to each share
                for share in shares[:5]:
                    if share.endswith("$"):
                        continue
                    stdout2, _, rc2 = _run_cmd(
                        ["smbclient", f"//{safe}/{share}", "-N", "-c", "ls"],
                        timeout=10,
                    )
                    if rc2 == 0 and stdout2:
                        vulns.append({
                            "tipo": "SMB_SHARE_ACCESSIBLE",
                            "share": share,
                            "amostra": stdout2[:200],
                            "severidade": "CRITICO",
                            "descricao": f"Share '{share}' acessível sem autenticação!",
                            "remediao": "Restringir acesso ao share com autenticação.",
                        })

            if ipc_shares:
                vulns.append({
                    "tipo": "SMB_IPC_ACCESSIBLE",
                    "severidade": "MEDIO",
                    "descricao": "IPC$ acessível via null session — enumeration possível.",
                    "remediao": "Restringir IPC$ null session access.",
                })

        # Domain info via SMB
        stdout3, _, rc3 = _run_cmd(
            ["smbclient", "-L", f"//{safe}", "-N", "-d", "0"],
            timeout=10,
        )
        if rc3 == 0:
            domain_match = re.search(r"Domain=\[([^\]]+)\]", stdout3 + stderr)
            if domain_match:
                vulns.append({
                    "tipo": "SMB_DOMAIN_LEAKED",
                    "domain": domain_match.group(1),
                    "severidade": "MEDIO",
                    "descricao": f"Nome de domínio revelado: {domain_match.group(1)}",
                    "remediao": "Configurar signing e restringir null sessions.",
                })

    # RPCClient — user/group enumeration
    if tools.get("rpcclient"):
        stdout, _, rc = _run_cmd(
            ["rpcclient", "-U", "", "-N", safe, "-c", "enumdomusers"],
            timeout=15,
        )
        if rc == 0 and "user:" in stdout:
            users = re.findall(r"user:\[([^\]]+)\]", stdout)
            vulns.append({
                "tipo": "RPC_USER_ENUM",
                "users": users[:20],
                "total": len(users),
                "severidade": "ALTO",
                "descricao": f"RPC null session — {len(users)} usuários enumerados!",
                "remediao": "Desabilitar RPC null session. Usar NTLM auth.",
            })

        # Group enumeration
        stdout2, _, rc2 = _run_cmd(
            ["rpcclient", "-U", "", "-N", safe, "-c", "enumdomgroups"],
            timeout=15,
        )
        if rc2 == 0 and "group:" in stdout2:
            groups = re.findall(r"group:\[([^\]]+)\]", stdout2)
            vulns.append({
                "tipo": "RPC_GROUP_ENUM",
                "groups": groups[:20],
                "severidade": "MEDIO",
                "descricao": f"RPC null session — {len(groups)} grupos enumerados!",
                "remediao": "Desabilitar RPC null session.",
            })

    # enum4linux / enum4linux-ng
    enum_tool = "enum4linux-ng" if tools.get("enum4linux-ng") else ("enum4linux" if tools.get("enum4linux") else None)
    if enum_tool:
        stdout, _, rc = _run_cmd(
            [enum_tool, "-a", safe],
            timeout=60,
        )
        if rc == 0 and stdout:
            # Extract useful info
            if "Got domain" in stdout or "Domain:" in stdout:
                vulns.append({
                    "tipo": "ENUM4LINUX_FULL_ENUM",
                    "severidade": "ALTO",
                    "descricao": f"{enum_tool} completa — informações AD expostas!",
                    "remediao": "Habilitar SMB signing e desabilitar null sessions.",
                })

    return vulns


def _enum_ldap(target, tools):
    """Enumera LDAP — anonymous bind, root DSE, base DN."""
    vulns = []

    if not tools.get("ldapsearch"):
        return vulns

    # Root DSE (anonymous)
    stdout, _, rc = _run_cmd(
        ["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", "", "-s", "base",
         "(objectclass=*)", "namingContexts", "defaultNamingContext", "domainFunctionality"],
        timeout=15,
    )
    if rc == 0 and stdout:
        if "namingContexts:" in stdout:
            base_dns = re.findall(r"namingContexts:\s*(.+)", stdout)
            vulns.append({
                "tipo": "LDAP_ANONYMOUS_ROOT_DSE",
                "naming_contexts": [b.strip() for b in base_dns],
                "severidade": "ALTO",
                "descricao": "LDAP aceita bind anônimo — Root DSE acessível!",
                "remediao": "Desabilitar anonymous bind no LDAP. Requerir autenticação.",
            })

            # Enumerate users from discovered base DN
            for base_dn in base_dns:
                base_dn = base_dn.strip()
                if not base_dn:
                    continue
                stdout2, _, rc2 = _run_cmd(
                    ["ldapsearch", "-x", "-H", f"ldap://{target}",
                     "-b", base_dn, "(objectClass=user)",
                     "sAMAccountName", "distinguishedName", "memberOf"],
                    timeout=30,
                )
                if rc2 == 0 and "sAMAccountName:" in stdout2:
                    users = re.findall(r"sAMAccountName:\s*(.+)", stdout2)
                    vulns.append({
                        "tipo": "LDAP_USER_ENUM",
                        "base_dn": base_dn,
                        "users": [u.strip() for u in users[:30]],
                        "total": len(users),
                        "severidade": "CRITICO",
                        "descricao": f"LDAP anônimo — {len(users)} usuários enumerados!",
                        "remediao": "Desabilitar anonymous bind. Usar LDAPS.",
                    })

                # Enumerate groups
                stdout3, _, rc3 = _run_cmd(
                    ["ldapsearch", "-x", "-H", f"ldap://{target}",
                     "-b", base_dn, "(objectClass=group)", "cn", "description"],
                    timeout=30,
                )
                if rc3 == 0 and "cn:" in stdout3:
                    groups = re.findall(r"cn:\s*(.+)", stdout3)
                    vulns.append({
                        "tipo": "LDAP_GROUP_ENUM",
                        "base_dn": base_dn,
                        "groups": [g.strip() for g in groups[:20]],
                        "severidade": "ALTO",
                        "descricao": f"LDAP anônimo — {len(groups)} grupos enumerados!",
                        "remediao": "Desabilitar anonymous bind.",
                    })

        # Check for LDAP over non-standard ports
    for port in [389, 636, 3268, 3269]:
        try:
            stdout, _, rc = _run_cmd(
                ["ldapsearch", "-x", "-H", f"ldap://{target}:{port}", "-b", "", "-s", "base"],
                timeout=10,
            )
            if rc == 0:
                proto = "LDAPS" if port in [636, 3269] else "LDAP"
                gc = " (Global Catalog)" if port in [3268, 3269] else ""
                vulns.append({
                    "tipo": "LDAP_PORT_OPEN",
                    "porta": port,
                    "protocolo": proto,
                    "global_catalog": port in [3268, 3269],
                    "severidade": "INFO",
                    "descricao": f"{proto}{gc} acessível em :{port}",
                })
        except Exception:
            continue

    return vulns


def _enum_kerberos(target, tools):
    """Enumera Kerberos — AS-REP roasting, SPN enumeration."""
    vulns = []

    # AS-REP Roasting (users without pre-auth)
    if tools.get("impacket-GetNPUsers"):
        stdout, _, rc = _run_cmd(
            ["impacket-GetNPUsers", f"{target}/", "-usersfile", "/dev/stdin", "-no-pass", "-dc-ip", target],
            timeout=30,
        )
        if rc == 0 and "$krb5asrep$" in stdout:
            vulns.append({
                "tipo": "KERBEROS_ASREP_ROASTABLE",
                "severidade": "CRITICO",
                "descricao": "AS-REP roasting possível — usuários sem pre-auth!",
                "remediao": "Habilitar pre-authentication para todos os usuários.",
            })

    # SPN Enumeration (Kerberoasting)
    if tools.get("impacket-GetUserSPNs"):
        stdout, _, rc = _run_cmd(
            ["impacket-GetUserSPNs", f"{target}/", "-dc-ip", target, "-no-pass"],
            timeout=30,
        )
        if rc == 0 and "SPN" in stdout:
            vulns.append({
                "tipo": "KERBEROS_SPN_ENUM",
                "severidade": "ALTO",
                "descricao": "SPN enumeration possível — Kerberoasting!",
                "remediao": "Usar Group Managed Service Accounts (gMSA).",
            })

    # Kinit test (anonymous)
    if shutil.which("kinit"):
        stdout, _, rc = _run_cmd(
            ["kinit", "-n", f"@{target.upper()}"],
            timeout=10,
        )
        if rc == 0:
            vulns.append({
                "tipo": "KERBEROS_ANONYMOUS_TICKET",
                "severidade": "ALTO",
                "descricao": "Kerberos anonymous TGT obtido!",
                "remediao": "Restringir anonymous Kerberos access.",
            })

    # Check for Kerberos ports
    for port in [88, 464, 749]:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                service = {88: "Kerberos KDC", 464: "kpasswd", 749: "kadmin"}[port]
                vulns.append({
                    "tipo": "KERBEROS_PORT_OPEN",
                    "porta": port,
                    "service": service,
                    "severidade": "INFO",
                    "descricao": f"{service} acessível em :{port}",
                })
        except Exception:
            continue

    return vulns


def _check_ad_misconfigs(target, tools):
    """Verifica misconfigurations comuns de AD."""
    vulns = []

    # SMB Signing check
    if tools.get("crackmapexec"):
        stdout, _, rc = _run_cmd(
            ["crackmapexec", "smb", target, "--gen-relay-list", "/dev/null"],
            timeout=20,
        )
        output = stdout + _
        if "SMBv1" in output:
            vulns.append({
                "tipo": "SMBV1_ENABLED",
                "severidade": "ALTO",
                "descricao": "SMBv1 habilitado — vulnerável a EternalBlue e relay attacks!",
                "remediao": "Desabilitar SMBv1. Usar apenas SMBv2/v3.",
            })

    # SMB Signing via nmap
    if tools.get("nmap"):
        stdout, _, rc = _run_cmd(
            ["nmap", "-p", "445", "--script", "smb2-security-mode", target],
            timeout=30,
        )
        if "message_signing" in stdout:
            if "disabled" in stdout.lower() or "not required" in stdout.lower():
                vulns.append({
                    "tipo": "SMB_SIGNING_DISABLED",
                    "severidade": "ALTO",
                    "descricao": "SMB signing desabilitado — NTLM relay possível!",
                    "remediao": "Habilitar SMB signing obrigatório via GPO.",
                })

    # Check for LDAP signing
    if tools.get("nmap"):
        stdout, _, rc = _run_cmd(
            ["nmap", "-p", "389", "--script", "ldap-rootdse", target],
            timeout=30,
        )
        if "LDAP" in stdout:
            vulns.append({
                "tipo": "LDAP_NO_SIGNING",
                "severidade": "MEDIO",
                "descricao": "LDAP sem signing — NTLM relay possível!",
                "remediao": "Habilitar LDAP signing e channel binding.",
            })

    # Check for MFA bypass indicators
    try:
        resp = requests.get(f"http://{target}/adfs/ls/idpinitiatedsignon.aspx", timeout=5)
        if resp.status_code == 200:
            vulns.append({
                "tipo": "ADFS_EXPOSED",
                "severidade": "ALTO",
                "descricao": "ADFS login page exposta — possíveis ataques de password spray!",
                "remediao": "Restringir ADFS access. Implementar MFA.",
            })
    except Exception:
        pass

    # Check for NTLM
    try:
        resp = requests.get(f"http://{target}/", timeout=5)
        if "NTLM" in resp.headers.get("WWW-Authenticate", ""):
            vulns.append({
                "tipo": "NTLM_AUTH_EXPOSED",
                "severidade": "MEDIO",
                "descricao": "NTLM authentication exposta — relay/relay attacks!",
                "remediao": "Migrar para Kerberos. Habilitar EPA e channel binding.",
            })
    except Exception:
        pass

    return vulns


def _check_unconstrained_delegation(target, tools):
    """Detecta unconstrained delegation."""
    vulns = []

    if tools.get("impacket-findDelegation"):
        stdout, _, rc = _run_cmd(
            ["impacket-findDelegation", f"{target}/", "-dc-ip", target],
            timeout=30,
        )
        if rc == 0 and stdout:
            if "Unconstrained" in stdout:
                vulns.append({
                    "tipo": "UNCONSTRAINED_DELEGATION",
                    "severidade": "CRITICO",
                    "descricao": "Unconstrained delegation detectada — TGT extraction possível!",
                    "remediao": "Migrar para constrained delegation ou RBCD.",
                })
            elif "Constrained" in stdout:
                vulns.append({
                    "tipo": "CONSTRAINED_DELEGATION",
                    "severidade": "ALTO",
                    "descricao": "Constrained delegation detectada.",
                    "remediao": "Auditar S4U2Proxy permissions.",
                })

    # Check via LDAP (if available)
    if tools.get("ldapsearch"):
        stdout, _, rc = _run_cmd(
            ["ldapsearch", "-x", "-H", f"ldap://{target}",
             "-b", "", "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
             "sAMAccountName", "userAccountControl"],
            timeout=20,
        )
        if rc == 0 and "sAMAccountName:" in stdout:
            hosts = re.findall(r"sAMAccountName:\s*(.+)", stdout)
            vulns.append({
                "tipo": "UNCONSTRAINED_DELEGATION_LDAP",
                "hosts": [h.strip() for h in hosts],
                "severidade": "CRITICO",
                "descricao": f"Unconstrained delegation via LDAP — {len(hosts)} hosts!",
                "remediao": "Migrar para constrained delegation ou RBCD.",
            })

    return vulns


def _check_poisoning_opportunities(target):
    """Verifica oportunidades de LLMNR/NBT-NS/mDNS poisoning."""
    vulns = []

    # LLMNR (UDP 5355)
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, 5355))
        sock.close()
        if result == 0:
            vulns.append({
                "tipo": "LLMNR_ENABLED",
                "porta": 5355,
                "severidade": "ALTO",
                "descricao": "LLMNR habilitado — poisoning via Responder possível!",
                "remediao": "Desabilitar LLMNR via GPO: Turn Off Multicast Name Resolution.",
            })
    except Exception:
        pass

    # NBT-NS (UDP 137)
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, 137))
        sock.close()
        if result == 0:
            vulns.append({
                "tipo": "NBTNS_ENABLED",
                "porta": 137,
                "severidade": "ALTO",
                "descricao": "NBT-NS habilitado — poisoning via Responder possível!",
                "remediao": "Desabilitar NBT-NS nas interfaces de rede.",
            })
    except Exception:
        pass

    # mDNS (UDP 5353)
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, 5353))
        sock.close()
        if result == 0:
            vulns.append({
                "tipo": "MDNS_ENABLED",
                "porta": 5353,
                "severidade": "MEDIO",
                "descricao": "mDNS habilitado — poisoning possível!",
                "remediao": "Desabilitar mDNS se não necessário.",
            })
    except Exception:
        pass

    # WPAD check
    try:
        resp = requests.get(f"http://{target}/wpad.dat", timeout=5)
        if resp.status_code == 200 and ("PROXY" in resp.text or "FindProxyForURL" in resp.text):
            vulns.append({
                "tipo": "WPAD_EXPOSED",
                "severidade": "ALTO",
                "descricao": "WPAD exposto — proxy auto-config poisoning possível!",
                "remediao": "Remover registro WPAD do DNS. Bloquear wpad.dat no webserver.",
            })
    except Exception:
        pass

    return vulns


def _network_ad_checks(target):
    """Verificações de rede para AD."""
    vulns = []

    # Check common AD ports
    ad_ports = {
        53: "DNS",
        88: "Kerberos",
        135: "RPC Endpoint Mapper",
        139: "NetBIOS",
        389: "LDAP",
        445: "SMB",
        464: "kpasswd",
        636: "LDAPS",
        3268: "LDAP Global Catalog",
        3269: "LDAPS Global Catalog",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        9389: "ADWS",
    }

    import socket
    open_ports = []
    for port, service in ad_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ports.append({"porta": port, "servico": service})
        except Exception:
            continue

    if open_ports:
        vulns.append({
            "tipo": "AD_PORTS_OPEN",
            "ports": open_ports,
            "severidade": "INFO",
            "descricao": f"{len(open_ports)} portas AD abertas — servidor provavelmente é Domain Controller.",
        })

        # If DC ports are open, classify as DC
        dc_indicators = {88, 389, 445, 3268}
        open_port_nums = {p["porta"] for p in open_ports}
        if dc_indicators.issubset(open_port_nums):
            vulns.append({
                "tipo": "DOMAIN_CONTROLLER_DETECTED",
                "severidade": "INFO",
                "descricao": "Domain Controller detectado — portas Kerberos/LDAP/SMB/GC abertas.",
            })

    return vulns
