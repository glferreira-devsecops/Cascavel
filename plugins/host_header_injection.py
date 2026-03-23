# plugins/host_header_injection.py
def run(target, ip, open_ports, banners):
    """
    Scanner Host Header Injection.
    Testa manipulação do header Host para password reset poisoning,
    cache poisoning e web cache deception.
    """
    import requests

    vulns = []
    test_host = "evil.cascavel-test.com"
    pages = ["/", "/login", "/forgot-password", "/reset-password",
             "/api/", "/admin/"]

    for page in pages:
        url = f"http://{target}{page}"

        # 1. Host header override
        try:
            resp = requests.get(url, headers={"Host": test_host}, timeout=5)
            if test_host in resp.text:
                vulns.append({
                    "tipo": "HOST_HEADER_INJECTION",
                    "pagina": page,
                    "severidade": "ALTO",
                    "descricao": "Host injetado refletido na resposta",
                })
        except Exception:
            pass

        # 2. X-Forwarded-Host
        try:
            resp = requests.get(url, headers={"X-Forwarded-Host": test_host}, timeout=5)
            if test_host in resp.text:
                vulns.append({
                    "tipo": "X_FORWARDED_HOST_INJECTION",
                    "pagina": page,
                    "severidade": "ALTO",
                })
        except Exception:
            pass

        # 3. X-Forwarded-For bypass (acesso a áreas restritas)
        try:
            resp_normal = requests.get(url, timeout=5)
            resp_bypass = requests.get(url, headers={"X-Forwarded-For": "127.0.0.1"}, timeout=5)
            if resp_normal.status_code in [401, 403] and resp_bypass.status_code == 200:
                vulns.append({
                    "tipo": "IP_BYPASS_VIA_XFF",
                    "pagina": page,
                    "severidade": "CRITICO",
                    "descricao": "Access control bypass via X-Forwarded-For: 127.0.0.1",
                })
        except Exception:
            pass

        # 4. Double Host header
        try:
            resp = requests.get(url, headers={"Host": f"{target}\r\nX-Injected: test"}, timeout=5)
            if "X-Injected" in str(resp.headers):
                vulns.append({
                    "tipo": "HOST_HEADER_CRLF",
                    "pagina": page,
                    "severidade": "CRITICO",
                })
        except Exception:
            pass

    return {"plugin": "host_header_injection", "resultados": vulns if vulns else "Nenhum Host Header Injection detectado"}
