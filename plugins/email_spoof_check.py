# plugins/email_spoof_check.py
import shlex
import subprocess

DMARC_POLICIES = {"none": "CRITICO", "quarantine": "MEDIO", "reject": "BAIXO"}


def _query_dns_txt(domain, prefix=""):
    """Consulta registros TXT do DNS via socket."""
    full = f"{prefix}{domain}" if prefix else domain
    safe_full = shlex.quote(full)
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", safe_full],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _check_spf(domain):
    """Verifica registro SPF do domínio."""
    vulns = []
    txt = _query_dns_txt(domain)
    if "v=spf1" not in txt:
        vulns.append(
            {
                "tipo": "SPF_AUSENTE",
                "severidade": "CRITICO",
                "descricao": "SPF ausente — email spoofing trivial!",
            }
        )
    elif "+all" in txt:
        vulns.append(
            {
                "tipo": "SPF_PERMISSIVE",
                "severidade": "CRITICO",
                "descricao": "SPF com +all — qualquer servidor pode enviar!",
            }
        )
    elif "~all" in txt:
        vulns.append(
            {
                "tipo": "SPF_SOFTFAIL",
                "severidade": "MEDIO",
                "descricao": "SPF com ~all (softfail) — spoofing possível em alguns MTAs",
            }
        )
    return vulns


def _check_dmarc(domain):
    """Verifica registro DMARC do domínio."""
    vulns = []
    txt = _query_dns_txt(domain, prefix="_dmarc.")
    if "v=DMARC1" not in txt:
        vulns.append(
            {
                "tipo": "DMARC_AUSENTE",
                "severidade": "CRITICO",
                "descricao": "DMARC ausente — sem enforcement de email authentication!",
            }
        )
    else:
        for policy, sev in DMARC_POLICIES.items():
            if f"p={policy}" in txt:
                if policy == "none":
                    vulns.append(
                        {
                            "tipo": "DMARC_NONE",
                            "severidade": sev,
                            "descricao": "DMARC p=none — monitoring only, sem enforcement!",
                        }
                    )
                break
    return vulns


def _check_dkim_selector(domain):
    """Verifica seletores DKIM comuns."""
    vulns = []
    selectors = ["default", "google", "selector1", "selector2", "dkim", "mail", "k1"]
    found = False
    for sel in selectors:
        txt = _query_dns_txt(domain, prefix=f"{sel}._domainkey.")
        if "v=DKIM1" in txt or "p=" in txt:
            found = True
            break
    if not found:
        vulns.append(
            {
                "tipo": "DKIM_NAO_DETECTADO",
                "severidade": "ALTO",
                "descricao": "Nenhum seletor DKIM comum encontrado — verificar manualmente",
            }
        )
    return vulns


def run(target, ip, open_ports, banners):
    """
    Verificação de SPF/DKIM/DMARC para email spoofing.
    2026 Intel: BEC (Business Email Compromise) prevention,
    DMARC enforcement, SPF bypass techniques, DKIM validation.
    """
    _ = (ip, open_ports, banners)  # Standardized plugin signature
    vulns = []
    vulns.extend(_check_spf(target))
    vulns.extend(_check_dmarc(target))
    vulns.extend(_check_dkim_selector(target))

    return {
        "plugin": "email_spoof_check",
        "resultados": vulns if vulns else "Email authentication configurada corretamente",
    }
