# plugins/email_harvester.py — Cascavel 2026 Intelligence
import re
import shlex
import subprocess

import requests

PAGES = [
    "/",
    "/contact",
    "/about",
    "/team",
    "/impressum",
    "/privacy",
    "/legal",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/staff",
    "/careers",
    "/jobs",
    "/support",
    "/help",
]

IMG_EXTS = (".png", ".jpg", ".gif", ".css", ".js", ".ico", ".svg", ".woff")

# ──────────── COMMON EMAIL PREFIXES ────────────
COMMON_PREFIXES = [
    "admin",
    "info",
    "contact",
    "support",
    "security",
    "abuse",
    "postmaster",
    "webmaster",
    "noreply",
    "no-reply",
    "help",
    "sales",
    "marketing",
    "hr",
    "careers",
    "billing",
    "finance",
    "legal",
    "compliance",
    "privacy",
    "ceo",
    "cto",
    "cfo",
    "dev",
    "engineering",
    "ops",
    "devops",
    "tech",
]


def _scrape_emails(target, pages):
    """Scrape emails from web pages."""
    email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    emails = set()

    for page in pages:
        url = f"http://{target}{page}"
        try:
            resp = requests.get(url, timeout=6)
            if resp.status_code == 200:
                found = email_pattern.findall(resp.text)
                for e in found:
                    if not e.lower().endswith(IMG_EXTS):
                        emails.add(e.lower())
        except Exception:
            continue

    return emails


def _extract_mailto(target):
    """Extrai emails de links mailto."""
    emails = set()
    try:
        resp = requests.get(f"http://{target}/", timeout=6)
        if resp.status_code == 200:
            mailto = re.findall(r"mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", resp.text, re.IGNORECASE)
            for e in mailto:
                emails.add(e.lower())
    except Exception:
        pass
    return emails


def _get_mx_records(target):
    """Obtém registros MX."""
    safe_target = shlex.quote(target)
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", safe_target],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _check_email_security(target):
    """Verifica SPF e DMARC para spoofing assessment."""
    safe_target = shlex.quote(target)
    security = {}
    try:
        spf = subprocess.run(
            ["dig", "+short", "TXT", safe_target],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in spf.stdout.splitlines():
            if "v=spf1" in line:
                security["spf"] = line.strip()[:100]
                if "~all" in line:
                    security["spf_policy"] = "SOFTFAIL (emails spoofados podem ser entregues)"
                elif "-all" in line:
                    security["spf_policy"] = "HARDFAIL (proteção forte)"
                elif "+all" in line:
                    security["spf_policy"] = "ALLOW ALL (SEM PROTEÇÃO!)"
    except Exception:
        pass

    try:
        dmarc = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{safe_target}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in dmarc.stdout.splitlines():
            if "v=DMARC1" in line:
                security["dmarc"] = line.strip()[:100]
                if "p=none" in line:
                    security["dmarc_policy"] = "NONE (monitoramento apenas — sem bloqueio!)"
                elif "p=quarantine" in line:
                    security["dmarc_policy"] = "QUARANTINE (emails suspeitos para spam)"
                elif "p=reject" in line:
                    security["dmarc_policy"] = "REJECT (proteção máxima)"
    except Exception:
        pass

    return security


def run(target, ip, open_ports, banners):
    """
    Email Harvester 2026-Grade — Web Scrape, DNS, Security Assessment.

    Técnicas: 15 pages scraping, mailto extraction, MX record lookup,
    SPF/DMARC policy analysis (softfail/hardfail/allow-all),
    23 common email prefixes for inference, domain/external email separation.
    """
    _ = (ip, open_ports, banners)
    resultado = {}

    # Web scraping
    emails = _scrape_emails(target, PAGES)

    # Mailto extraction
    mailto_emails = _extract_mailto(target)
    emails.update(mailto_emails)

    # MX records
    resultado["mx_records"] = _get_mx_records(target)

    # Email security
    resultado["email_security"] = _check_email_security(target)

    # Inferred emails
    resultado["emails_inferidos"] = [f"{prefix}@{target}" for prefix in COMMON_PREFIXES]

    # Categorize
    domain_emails = sorted([e for e in emails if target in e])
    other_emails = sorted([e for e in emails if target not in e])

    resultado["emails_do_dominio"] = domain_emails if domain_emails else "Nenhum encontrado"
    resultado["emails_externos"] = other_emails[:20] if other_emails else "Nenhum encontrado"
    resultado["total_unico"] = len(emails)

    return {
        "plugin": "email_harvester",
        "versao": "2026.1",
        "tecnicas": ["web_scraping", "mailto_extraction", "mx_lookup", "spf_dmarc_analysis", "email_inference"],
        "resultados": resultado,
    }
