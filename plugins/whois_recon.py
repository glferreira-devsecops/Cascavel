# plugins/whois_recon.py — Cascavel 2026 Intelligence
"""
WHOIS/RDAP Deep Reconnaissance — Cascavel Elite Plugin.

Técnicas: WHOIS nativo (subprocess), RDAP JSON API (IANA bootstrap),
registrar/abuse extraction, nameserver enumeration, domain age analysis,
DNSSEC detection, privacy/proxy WHOIS detection, IP WHOIS (network range/ASN),
creation/expiry date extraction, registrant org/country mapping.
"""

import datetime
import re
import shlex
import shutil
import subprocess

import requests

RDAP_BOOTSTRAP = "https://rdap.org/domain/"
IP_RDAP_BOOTSTRAP = "https://rdap.org/ip/"

PRIVACY_INDICATORS = [
    "whoisguard",
    "privacyguard",
    "domains by proxy",
    "privacy protect",
    "contact privacy",
    "whois privacy",
    "redacted for privacy",
    "data protected",
    "withheld for privacy",
    "identity protect",
    "private registration",
    "perfect privacy",
    "domainsbyproxy",
]

REGISTRAR_RISK = {
    "namecheap": "MEDIO",
    "godaddy": "BAIXO",
    "porkbun": "MEDIO",
    "epik": "ALTO",
    "njalla": "CRITICO",
    "tucows": "BAIXO",
    "cloudflare": "BAIXO",
    "gandi": "BAIXO",
}


def _whois_native(target):
    """Executa whois nativo e extrai campos."""
    if not shutil.which("whois"):
        return None
    try:
        proc = subprocess.run(
            ["whois", shlex.quote(target).strip("'")],
            capture_output=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
        )
        return proc.stdout if proc.returncode == 0 else None
    except Exception:
        return None


def _parse_whois(raw):
    """Parse campos do WHOIS raw text."""
    if not raw:
        return {}
    fields = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
        "expiry_date": r"(?:Expir(?:y|ation)\s*Date|Registry Expiry Date):\s*(.+)",
        "updated_date": r"Updated\s*Date:\s*(.+)",
        "registrant_org": r"Registrant\s*Organization:\s*(.+)",
        "registrant_country": r"Registrant\s*(?:Country|State):\s*(.+)",
        "registrant_email": r"Registrant\s*Email:\s*(.+)",
        "admin_email": r"Admin\s*Email:\s*(.+)",
        "tech_email": r"Tech\s*Email:\s*(.+)",
        "abuse_email": r"(?:Abuse.*Email|OrgAbuseEmail):\s*(.+)",
        "abuse_phone": r"(?:Abuse.*Phone|OrgAbusePhone):\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
        "status": r"(?:Domain\s*)?Status:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            fields[key] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]

    # Nameservers
    ns = re.findall(r"Name\s*Server:\s*(.+)", raw, re.IGNORECASE)
    if ns:
        fields["nameservers"] = [n.strip().lower() for n in ns]

    # Network range (IP WHOIS)
    cidr = re.findall(r"CIDR:\s*(.+)", raw, re.IGNORECASE)
    if cidr:
        fields["cidr"] = cidr[0].strip()
    netrange = re.findall(r"NetRange:\s*(.+)", raw, re.IGNORECASE)
    if netrange:
        fields["netrange"] = netrange[0].strip()
    orgname = re.findall(r"OrgName:\s*(.+)", raw, re.IGNORECASE)
    if orgname:
        fields["org_name"] = orgname[0].strip()
    asn = re.findall(r"OriginAS:\s*(.+)", raw, re.IGNORECASE)
    if asn:
        fields["asn"] = asn[0].strip()

    return fields


def _rdap_lookup(target):
    """RDAP JSON lookup — structured data."""
    try:
        resp = requests.get(f"{RDAP_BOOTSTRAP}{target}", timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _rdap_ip_lookup(ip):
    """RDAP IP lookup — network/ASN info."""
    try:
        resp = requests.get(f"{IP_RDAP_BOOTSTRAP}{ip}", timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _extract_rdap_info(rdap):
    """Extrai informações úteis do RDAP JSON."""
    if not rdap:
        return {}
    info = {}
    # Events (creation, expiration)
    for event in rdap.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            info["creation_date"] = date
        elif action == "expiration":
            info["expiry_date"] = date
        elif action == "last changed":
            info["updated_date"] = date

    # Nameservers
    ns_list = rdap.get("nameservers", [])
    if ns_list:
        info["nameservers"] = [ns.get("ldhName", "").lower() for ns in ns_list]

    # Entities (registrar, registrant)
    for entity in rdap.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])
        name = ""
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and item[0] == "fn":
                    name = item[3] if len(item) > 3 else ""
        if "registrar" in roles and name:
            info["registrar"] = name
        if "registrant" in roles and name:
            info["registrant"] = name

    # DNSSEC
    if rdap.get("secureDNS", {}).get("delegationSigned"):
        info["dnssec"] = "signed"

    # Status
    info["status"] = rdap.get("status", [])

    return info


def _analyze_domain_age(creation_date_str):
    """Analisa idade do domínio para risk scoring."""
    if not creation_date_str:
        return None
    try:
        # Try ISO format
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"]:
            try:
                created = datetime.datetime.strptime(creation_date_str[:19], fmt[: len(creation_date_str[:19])])
                age_days = (datetime.datetime.now() - created).days
                return {
                    "created": creation_date_str,
                    "age_days": age_days,
                    "age_years": round(age_days / 365.25, 1),
                    "risk": "CRITICO"
                    if age_days < 30
                    else "ALTO"
                    if age_days < 180
                    else "MEDIO"
                    if age_days < 365
                    else "BAIXO",
                    "nota": "Domínio muito recente — possível phishing!"
                    if age_days < 30
                    else "Domínio jovem"
                    if age_days < 365
                    else "Domínio estabelecido",
                }
            except ValueError:
                continue
    except Exception:
        pass
    return None


def _detect_privacy(whois_fields, raw_whois):
    """Detecta WHOIS privacy/proxy services."""
    text = (raw_whois or "").lower()
    for indicator in PRIVACY_INDICATORS:
        if indicator in text:
            return {
                "privacy_detected": True,
                "service": indicator,
                "nota": "WHOIS privacy service ativo — dados do registrante ocultos",
            }
    registrant = str(whois_fields.get("registrant_org", "")).lower()
    for indicator in PRIVACY_INDICATORS:
        if indicator in registrant:
            return {"privacy_detected": True, "service": indicator}
    return {"privacy_detected": False}


def _assess_registrar_risk(registrar):
    """Avalia risco baseado no registrar (bullet-proof hosting, etc)."""
    if not registrar:
        return None
    reg_lower = registrar.lower()
    for name, risk in REGISTRAR_RISK.items():
        if name in reg_lower:
            return {"registrar": registrar, "risk": risk}
    return {"registrar": registrar, "risk": "INFO"}


def _check_expiry(expiry_str):
    """Verifica se domínio está próximo de expirar."""
    if not expiry_str:
        return None
    try:
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"]:
            try:
                expiry = datetime.datetime.strptime(expiry_str[:19], fmt[: len(expiry_str[:19])])
                days_left = (expiry - datetime.datetime.now()).days
                return {
                    "expiry_date": expiry_str,
                    "days_remaining": days_left,
                    "risk": "CRITICO"
                    if days_left < 0
                    else "ALTO"
                    if days_left < 30
                    else "MEDIO"
                    if days_left < 90
                    else "BAIXO",
                    "nota": "DOMÍNIO EXPIRADO!"
                    if days_left < 0
                    else f"Expira em {days_left} dias"
                    if days_left < 90
                    else "OK",
                }
            except ValueError:
                continue
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner WHOIS/RDAP 2026-Grade — Domain & IP Intelligence.

    Técnicas: WHOIS nativo (15+ campos), RDAP JSON API (structured data),
    IP WHOIS (network range/ASN/org), domain age analysis (risk scoring),
    registrar risk assessment, WHOIS privacy detection (10+ indicators),
    nameserver enumeration, DNSSEC detection, expiry monitoring,
    abuse contact extraction.
    """
    _ = (open_ports, banners)
    resultado = {"domain_whois": {}, "ip_whois": {}, "vulns": [], "intel": {}}

    # 1. Domain WHOIS (native)
    raw_whois = _whois_native(target)
    whois_fields = _parse_whois(raw_whois)
    resultado["domain_whois"] = whois_fields

    # 2. RDAP (structured JSON)
    rdap_data = _rdap_lookup(target)
    rdap_info = _extract_rdap_info(rdap_data)
    if rdap_info:
        resultado["rdap"] = rdap_info
        # Merge missing fields
        for k, v in rdap_info.items():
            if k not in whois_fields:
                whois_fields[k] = v

    # 3. IP WHOIS
    if ip and ip != "N/A":
        raw_ip_whois = _whois_native(ip)
        ip_fields = _parse_whois(raw_ip_whois)
        resultado["ip_whois"] = ip_fields

        rdap_ip = _rdap_ip_lookup(ip)
        if rdap_ip:
            resultado["ip_rdap"] = {
                "name": rdap_ip.get("name", ""),
                "handle": rdap_ip.get("handle", ""),
                "startAddress": rdap_ip.get("startAddress", ""),
                "endAddress": rdap_ip.get("endAddress", ""),
                "type": rdap_ip.get("type", ""),
            }

    # 4. Domain Age Analysis
    creation = whois_fields.get("creation_date")
    if isinstance(creation, list):
        creation = creation[0]
    age_info = _analyze_domain_age(str(creation) if creation else None)
    if age_info:
        resultado["intel"]["domain_age"] = age_info
        if age_info.get("risk") in ("CRITICO", "ALTO"):
            resultado["vulns"].append(
                {
                    "tipo": "DOMAIN_AGE_SUSPICIOUS",
                    "severidade": age_info["risk"],
                    "descricao": age_info.get("nota", "Domínio recente"),
                    "age_days": age_info.get("age_days"),
                }
            )

    # 5. Privacy Detection
    privacy = _detect_privacy(whois_fields, raw_whois)
    resultado["intel"]["privacy"] = privacy

    # 6. Registrar Risk
    registrar = whois_fields.get("registrar")
    if isinstance(registrar, list):
        registrar = registrar[0]
    reg_risk = _assess_registrar_risk(registrar)
    if reg_risk:
        resultado["intel"]["registrar_risk"] = reg_risk
        if reg_risk.get("risk") in ("CRITICO", "ALTO"):
            resultado["vulns"].append(
                {
                    "tipo": "HIGH_RISK_REGISTRAR",
                    "severidade": reg_risk["risk"],
                    "registrar": registrar,
                    "descricao": f"Registrar de alto risco: {registrar}",
                }
            )

    # 7. Expiry Check
    expiry = whois_fields.get("expiry_date")
    if isinstance(expiry, list):
        expiry = expiry[0]
    exp_info = _check_expiry(str(expiry) if expiry else None)
    if exp_info:
        resultado["intel"]["expiry"] = exp_info
        if exp_info.get("risk") in ("CRITICO", "ALTO"):
            resultado["vulns"].append(
                {
                    "tipo": "DOMAIN_EXPIRY_RISK",
                    "severidade": exp_info["risk"],
                    "descricao": exp_info.get("nota", ""),
                    "days_remaining": exp_info.get("days_remaining"),
                }
            )

    # 8. DNSSEC
    dnssec = whois_fields.get("dnssec", "")
    if isinstance(dnssec, str) and dnssec.lower() in ("unsigned", "no"):
        resultado["vulns"].append(
            {
                "tipo": "DNSSEC_NOT_SIGNED",
                "severidade": "MEDIO",
                "descricao": "DNSSEC não habilitado — vulnerável a DNS spoofing!",
            }
        )

    # 9. Nameserver Analysis
    ns_list = whois_fields.get("nameservers", [])
    if ns_list:
        resultado["intel"]["nameservers"] = ns_list
        # Single NS = SPOF
        if len(ns_list) == 1:
            resultado["vulns"].append(
                {
                    "tipo": "SINGLE_NAMESERVER",
                    "severidade": "MEDIO",
                    "descricao": "Apenas 1 nameserver — single point of failure!",
                }
            )

    return {
        "plugin": "whois_recon",
        "versao": "2026.1",
        "tecnicas": [
            "whois_native",
            "rdap_json",
            "ip_whois",
            "domain_age",
            "privacy_detection",
            "registrar_risk",
            "expiry_check",
            "dnssec",
            "nameserver_analysis",
            "abuse_extraction",
        ],
        "resultados": resultado,
    }
