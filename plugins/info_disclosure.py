# plugins/info_disclosure.py
def run(target, ip, open_ports, banners):
    """
    Scanner de Information Disclosure.
    Busca arquivos sensíveis, backups, configs e debug endpoints expostos.
    """
    import requests

    sensitive_paths = [
        # Config / Env
        ("/.env", "ALTO", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "APP_KEY"]),
        ("/.env.production", "CRITICO", ["DB_PASSWORD", "SECRET_KEY"]),
        ("/.env.local", "ALTO", ["DB_PASSWORD", "SECRET_KEY"]),
        ("/config.php", "ALTO", ["password", "db_pass", "secret"]),
        ("/config.yaml", "ALTO", ["password", "secret", "key"]),
        ("/config.json", "ALTO", ["password", "secret", "key"]),
        ("/wp-config.php", "CRITICO", ["DB_PASSWORD", "AUTH_KEY"]),
        # Debug
        ("/debug", "MEDIO", []),
        ("/debug/vars", "ALTO", []),
        ("/phpinfo.php", "ALTO", ["PHP Version"]),
        ("/server-info", "ALTO", ["Server Version"]),
        ("/server-status", "MEDIO", []),
        ("/elmah.axd", "ALTO", []),
        # Backups
        ("/backup.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
        ("/backup.zip", "CRITICO", []),
        ("/db.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
        ("/database.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
        # VCS
        ("/.git/config", "CRITICO", ["[remote", "[branch"]),
        ("/.git/HEAD", "ALTO", ["ref:"]),
        ("/.svn/entries", "ALTO", []),
        ("/.hg/dirstate", "ALTO", []),
        # Keys / Creds
        ("/.htpasswd", "CRITICO", [":"]),
        ("/.htaccess", "MEDIO", []),
        ("/id_rsa", "CRITICO", ["PRIVATE KEY"]),
        ("/id_rsa.pub", "MEDIO", ["ssh-rsa"]),
        # Docker / CI
        ("/docker-compose.yml", "ALTO", ["services"]),
        ("/Dockerfile", "MEDIO", ["FROM"]),
        ("/.github/workflows/", "MEDIO", []),
        # Logs
        ("/error.log", "MEDIO", []),
        ("/access.log", "MEDIO", []),
        ("/debug.log", "MEDIO", []),
    ]

    vulns = []

    for path, severidade, indicators in sensitive_paths:
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, timeout=4)
            if resp.status_code == 200 and len(resp.text) > 10:
                if indicators:
                    found = [ind for ind in indicators if ind in resp.text]
                    if found:
                        vulns.append({
                            "tipo": "INFO_DISCLOSURE",
                            "path": path,
                            "severidade": severidade,
                            "indicadores": found,
                            "tamanho": len(resp.text),
                        })
                else:
                    vulns.append({
                        "tipo": "FILE_EXPOSED",
                        "path": path,
                        "severidade": severidade,
                        "tamanho": len(resp.text),
                    })
        except Exception:
            continue

    return {"plugin": "info_disclosure", "resultados": vulns if vulns else "Nenhuma information disclosure detectada"}
