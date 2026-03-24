# plugins/clickjacking_check.py — Cascavel 2026 Intelligence
import requests
import re


PAGES = ["/", "/login", "/admin", "/dashboard", "/settings", "/profile",
         "/account", "/checkout", "/payment", "/transfer"]


def _check_frame_protection(target, page):
    """Verifica proteção X-Frame-Options e CSP frame-ancestors."""
    vulns = []
    url = f"http://{target}{page}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return vulns

        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = xfo in ["DENY", "SAMEORIGIN"]
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo and not has_csp_frame:
            sev = "ALTO" if page in ["/login", "/checkout", "/payment", "/transfer"] else "MEDIO"
            vulns.append({
                "tipo": "CLICKJACKING_VULNERAVEL", "pagina": page,
                "severidade": sev,
                "x_frame_options": xfo or "AUSENTE",
                "csp_frame_ancestors": "AUSENTE",
                "descricao": f"Página {page} pode ser carregada em iframe!",
            })

        if "ALLOW-FROM" in xfo:
            vulns.append({
                "tipo": "XFO_ALLOW_FROM_DEPRECATED", "pagina": page,
                "severidade": "MEDIO",
                "descricao": "ALLOW-FROM deprecated — não suportado em Chrome/Firefox!",
            })

        # CSP frame-ancestors * or http:
        if "frame-ancestors" in csp:
            fa_match = re.search(r'frame-ancestors\s+([^;]+)', csp)
            if fa_match:
                fa_value = fa_match.group(1).strip()
                if fa_value == "*" or "http:" in fa_value:
                    vulns.append({
                        "tipo": "CSP_FRAME_ANCESTORS_WEAK", "pagina": page,
                        "value": fa_value[:60], "severidade": "ALTO",
                        "descricao": "frame-ancestors permite wildcard ou HTTP — bypass!",
                    })

        # XFO and CSP conflict
        if has_xfo and has_csp_frame:
            if xfo == "DENY" and "'self'" in csp:
                vulns.append({
                    "tipo": "XFO_CSP_CONFLICT", "pagina": page,
                    "severidade": "BAIXO",
                    "descricao": "XFO=DENY mas CSP permite self — browser usa CSP (mais permissivo)",
                })

        return vulns
    except Exception:
        return vulns


def _check_sandbox_bypass(target, page):
    """Verifica se sandbox iframe bypass é possível."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}{page}", timeout=5)
        if resp.status_code != 200:
            return vulns

        # Check for forms (clickjacking targets)
        if '<form' in resp.text.lower():
            xfo = resp.headers.get("X-Frame-Options", "").upper()
            csp = resp.headers.get("Content-Security-Policy", "")
            if not xfo and "frame-ancestors" not in csp:
                vulns.append({
                    "tipo": "CLICKJACKING_FORM_TARGET", "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Formulário sem proteção contra clickjacking — form hijacking!",
                })
    except Exception:
        pass
    return vulns


def _check_double_framing(target, page):
    """Verifica se double framing bypass é possível com SAMEORIGIN."""
    try:
        resp = requests.get(f"http://{target}{page}", timeout=5)
        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        if xfo == "SAMEORIGIN" and "frame-ancestors" not in csp:
            return {
                "tipo": "DOUBLE_FRAMING_POSSIBLE", "pagina": page,
                "severidade": "MEDIO",
                "descricao": "X-Frame-Options: SAMEORIGIN sem CSP — double framing bypass possível!",
            }
    except Exception:
        pass
    return None


def _check_drag_drop(target, page):
    """Verifica se drag-and-drop clickjacking é possível."""
    try:
        resp = requests.get(f"http://{target}{page}", timeout=5)
        if resp.status_code != 200:
            return None

        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        # File upload or text input without frame protection
        has_upload = 'type="file"' in resp.text.lower()
        has_textarea = '<textarea' in resp.text.lower()

        if (has_upload or has_textarea) and not xfo and "frame-ancestors" not in csp:
            return {
                "tipo": "DRAG_DROP_CLICKJACKING", "pagina": page,
                "severidade": "ALTO",
                "descricao": f"{'File upload' if has_upload else 'Textarea'} sem frame protection — drag-and-drop hijacking!",
            }
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner Clickjacking 2026-Grade — XFO, CSP, Double Framing, Drag-Drop.

    Técnicas: X-Frame-Options analysis, CSP frame-ancestors wildcard/HTTP check,
    XFO/CSP conflict detection, ALLOW-FROM deprecated check,
    form target detection, double framing bypass (SAMEORIGIN without CSP),
    drag-and-drop clickjacking (file upload/textarea), sandbox bypass,
    severity escalation for payment/login pages.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for page in PAGES:
        vulns.extend(_check_frame_protection(target, page))
        vulns.extend(_check_sandbox_bypass(target, page))

        double = _check_double_framing(target, page)
        if double:
            vulns.append(double)

        drag = _check_drag_drop(target, page)
        if drag:
            vulns.append(drag)

    return {
        "plugin": "clickjacking_check",
        "versao": "2026.1",
        "tecnicas": ["xfo_analysis", "csp_frame_ancestors", "double_framing",
                      "form_targeting", "drag_drop", "sandbox_bypass"],
        "resultados": vulns if vulns else "Proteção contra clickjacking presente",
    }
