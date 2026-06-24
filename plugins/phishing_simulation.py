"""
[+] Plugin: Phishing Simulation & Vulnerability Testing
[+] Description: Testa vetores de phishing — spoofing, credential harvesting, OAuth abuse, MFA bypass
[+] Category: Social Engineering / Phishing
[+] CVSS: 8.0 (High)
[+] Author: CASCAVEL Framework
"""

import re
import shlex
import subprocess
from typing import Any


def _query_dns_txt(domain: str, prefix: str = "") -> str:
    """Consulta registros TXT do DNS."""
    full = f"{prefix}{domain}" if prefix else domain
    safe = shlex.quote(full)
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", safe],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _query_dns_mx(domain: str) -> str:
    """Consulta registros MX do DNS."""
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", shlex.quote(domain)],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _check_spf_spoofing(domain: str) -> list[dict[str, Any]]:
    """Verifica vulnerabilidades SPF que permitem spoofing."""
    findings = []
    txt = _query_dns_txt(domain)
    if "v=spf1" not in txt:
        findings.append({
            "tipo": "SPF_AUSENTE",
            "severidade": "CRITICO",
            "descricao": "SPF ausente — qualquer servidor pode enviar emails como este domínio",
            "correcao": "Publicar registro SPF válido: v=spf1 include:_spf.google.com ~all",
        })
    elif "+all" in txt:
        findings.append({
            "tipo": "SPF_PERMISSIVO",
            "severidade": "CRITICO",
            "descricao": "SPF com +all — todos os servidores autorizados a enviar (trivial spoofing)",
            "correcao": "Trocar +all por -all ou ~all no registro SPF.",
        })
    elif "~all" in txt:
        findings.append({
            "tipo": "SPF_SOFTFAIL",
            "severidade": "MEDIO",
            "descricao": "SPF com ~all (softfail) — spoofing possível em alguns MTAs",
            "correcao": "Migrar para -all (hardfail) para bloquear spoofing efetivamente.",
        })
    elif "?all" in txt:
        findings.append({
            "tipo": "SPF_NEUTRAL",
            "severidade": "ALTO",
            "descricao": "SPF com ?all (neutral) — nenhuma política de restrição",
            "correcao": "Definir política -all ou ~all no registro SPF.",
        })
    return findings


def _check_dkim_phishing(domain: str) -> list[dict[str, Any]]:
    """Verifica se DKIM está ausente (permite forging)."""
    findings = []
    selectors = ["default", "google", "selector1", "selector2", "dkim", "mail", "k1", "s1", "s2"]
    found = False
    for sel in selectors:
        txt = _query_dns_txt(domain, f"{sel}._domainkey.")
        if "v=DKIM1" in txt or "p=" in txt:
            found = True
            # Check for weak key
            if "p=AAAAB3NzaC1yc2" in txt and len(txt) < 300:
                findings.append({
                    "tipo": "DKIM_WEAK_KEY",
                    "severidade": "ALTO",
                    "descricao": f"Chave DKIM curta/fraca no seletor '{sel}' — vulnerável a factorização",
                    "correcao": "Regenerar chave DKIM com tamanho mínimo 2048 bits.",
                })
            break
    if not found:
        findings.append({
            "tipo": "DKIM_AUSENTE",
            "severidade": "ALTO",
            "descricao": "Nenhum registro DKIM encontrado — emails podem ser forjados sem assinatura",
            "correcao": "Configurar DKIM com chave de 2048 bits no provedor de email.",
        })
    return findings


def _check_dmarc_enforcement(domain: str) -> list[dict[str, Any]]:
    """Verifica DMARC para proteção contra spoofing."""
    findings = []
    txt = _query_dns_txt(domain, "_dmarc.")
    if "v=DMARC1" not in txt:
        findings.append({
            "tipo": "DMARC_AUSENTE",
            "severidade": "CRITICO",
            "descricao": "DMARC ausente — sem proteção contra email spoofing/BEC",
            "correcao": "Publicar registro DMARC: v=DMARC1; p=reject; rua=mailto:dmarc-reports@dominio.com",
        })
    else:
        if "p=none" in txt:
            findings.append({
                "tipo": "DMARC_NONE",
                "severidade": "ALTO",
                "descricao": "DMARC p=none — modo monitor, sem enforcement de spoofing",
                "correcao": "Evoluir para p=quarantine e depois p=reject após análise dos reports.",
            })
        if "p=quarantine" in txt and "pct=" in txt:
            pct_match = re.search(r"pct=(\d+)", txt)
            if pct_match and int(pct_match.group(1)) < 100:
                findings.append({
                    "tipo": "DMARC_PARTIAL",
                    "severidade": "MEDIO",
                    "descricao": f"DMARC quarantine com pct={pct_match.group(1)}% — spoofing parcialmente possível",
                    "correcao": "Aumentar pct para 100% após validação.",
                })
        if "sp=none" in txt:
            findings.append({
                "tipo": "DMARC_SUBDOMAIN_NONE",
                "severidade": "ALTO",
                "descricao": "DMARC sp=none — subdomínios sem proteção contra spoofing",
                "correcao": "Definir sp=quarantine ou sp=reject para proteger subdomínios.",
            })
    return findings


def _check_credential_harvesting(target: str) -> list[dict[str, Any]]:
    """Verifica se o alvo tem páginas que podem ser clonadas para credential harvesting."""
    findings = []
    try:
        import requests
        login_paths = ["/login", "/signin", "/auth", "/oauth/authorize", "/sso", "/admin", "/wp-login.php"]
        for path in login_paths:
            try:
                url = f"https://{target}{path}"
                resp = requests.get(url, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code == 200 and ("password" in resp.text.lower() or "login" in resp.text.lower()):
                    # Check for anti-phishing protections
                    has_csrf = "csrf" in resp.text.lower() or "_token" in resp.text.lower()
                    has_origin_check = "origin" in str(resp.headers).lower()
                    protections = []
                    if has_csrf:
                        protections.append("CSRF token")
                    if has_origin_check:
                        protections.append("Origin check")
                    if not protections:
                        findings.append({
                            "tipo": "HARVESTING_SEM_PROTECAO",
                            "severidade": "ALTO",
                            "descricao": f"Página de login em {path} sem proteções anti-phishing visíveis",
                            "correcao": "Implementar CSRF token, origin validation, e alertas de domínio similar.",
                        })
            except Exception:
                continue
    except ImportError:
        pass
    return findings


def _check_oauth_phishing(target: str) -> list[dict[str, Any]]:
    """Verifica vetores de OAuth phishing."""
    findings = []
    try:
        import requests
        # Check for OAuth endpoints with open redirect
        oauth_paths = ["/oauth/authorize", "/auth/authorize", "/connect/authorize"]
        for path in oauth_paths:
            try:
                url = f"https://{target}{path}?redirect_uri=https://evil.com/callback&response_type=code"
                resp = requests.get(url, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code in [301, 302]:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append({
                            "tipo": "OAUTH_OPEN_REDIRECT",
                            "severidade": "CRITICO",
                            "descricao": f"OAuth endpoint {path} aceita redirect_uri arbitrário — phishing de tokens",
                            "evidencia": f"Redirect para: {location[:200]}",
                            "correcao": "Implementar whitelist estrita de redirect_uri no provider OAuth.",
                        })
                    elif resp.status_code == 200 and "authorize" in resp.text.lower():
                        findings.append({
                            "tipo": "OAUTH_SEM_VALIDACAO",
                            "severidade": "MEDIO",
                            "descricao": f"OAuth endpoint {path} retorna 200 sem redirect — verificar validação de redirect_uri",
                            "correcao": "Validar redirect_uri contra whitelist registrada.",
                        })
            except Exception:
                continue
    except ImportError:
        pass
    return findings


def _check_mfa_bypass(target: str) -> list[dict[str, Any]]:
    """Verifica técnicas conhecidas de bypass de MFA."""
    findings = []
    try:
        import requests
        # Check if MFA endpoint is bypassable via direct API access
        mfa_paths = ["/api/v1/users/me", "/api/user", "/api/authenticated"]
        session_paths = ["/api/session", "/api/token"]
        for path in mfa_paths:
            try:
                resp = requests.get(f"https://{target}{path}", timeout=5, verify=False)
                if resp.status_code == 200 and "user" in resp.text.lower():
                    findings.append({
                        "tipo": "MFA_BYPASS_API",
                        "severidade": "ALTO",
                        "descricao": f"Endpoint {path} acessível sem MFA — possível bypass via API direta",
                        "correcao": "Garantir que MFA é enforced em todos os endpoints, não apenas no UI.",
                    })
            except Exception:
                continue
        # Check for MFA rate limiting
        for path in session_paths:
            try:
                # Send rapid MFA attempts
                codes = ["000000", "123456", "111111"]
                responses = []
                for code in codes:
                    resp = requests.post(
                        f"https://{target}{path}",
                        json={"code": code},
                        timeout=3, verify=False
                    )
                    responses.append(resp.status_code)
                if all(r != 429 for r in responses):
                    findings.append({
                        "tipo": "MFA_SEM_RATE_LIMIT",
                        "severidade": "ALTO",
                        "descricao": f"MFA em {path} sem rate limiting — vulnerável a brute force de OTP",
                        "correcao": "Implementar rate limiting (max 5 tentativas) e lockout após falhas consecutivas.",
                    })
            except Exception:
                continue
    except ImportError:
        pass
    return findings


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Testa vetores de phishing e vulnerabilidades de email spoofing."""
    try:
        vulns = []
        _ = (ip, ports, banners)

        vulns.extend(_check_spf_spoofing(target))
        vulns.extend(_check_dkim_phishing(target))
        vulns.extend(_check_dmarc_enforcement(target))
        vulns.extend(_check_credential_harvesting(target))
        vulns.extend(_check_oauth_phishing(target))
        vulns.extend(_check_mfa_bypass(target))

        if context:
            email_config = context.get("email_config", {})
            if email_config.get("webmail_exposed"):
                vulns.append({
                    "tipo": "WEBMAIL_EXPOSTO",
                    "severidade": "ALTO",
                    "descricao": "Webmail exposto publicamente — aumenta superfície de phishing",
                    "correcao": "Restringir acesso ao webmail via VPN ou IP whitelist.",
                })

        return {
            "plugin": "phishing_simulation",
            "resultados": vulns if vulns else "Nenhum vetor de phishing crítico detectado",
        }
    except Exception as e:
        return {"plugin": "phishing_simulation", "erro": str(e)}
