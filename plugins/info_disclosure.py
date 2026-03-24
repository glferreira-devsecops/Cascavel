# plugins/info_disclosure.py — Cascavel 2026 Intelligence
import requests
import re


# ──────────── SENSITIVE PATHS (2026 Expanded) ────────────
SENSITIVE_PATHS = [
    # Environment files
    ("/.env", "CRITICO", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "APP_KEY", "AWS_SECRET"]),
    ("/.env.production", "CRITICO", ["DB_PASSWORD", "SECRET_KEY"]),
    ("/.env.local", "ALTO", ["DB_PASSWORD", "SECRET_KEY"]),
    ("/.env.staging", "ALTO", ["DB_PASSWORD", "SECRET_KEY"]),
    ("/.env.backup", "CRITICO", ["DB_PASSWORD", "SECRET_KEY"]),
    ("/.env.old", "CRITICO", ["DB_PASSWORD", "SECRET_KEY"]),
    # Config files
    ("/config.php", "ALTO", ["password", "db_pass", "secret"]),
    ("/config.yaml", "ALTO", ["password", "secret", "key"]),
    ("/config.json", "ALTO", ["password", "secret", "key"]),
    ("/wp-config.php", "CRITICO", ["DB_PASSWORD", "AUTH_KEY"]),
    ("/settings.py", "CRITICO", ["SECRET_KEY", "DATABASE"]),
    ("/application.properties", "ALTO", ["password", "secret"]),
    ("/application.yml", "ALTO", ["password", "datasource"]),
    # Debug/Admin
    ("/debug", "MEDIO", []),
    ("/debug/vars", "ALTO", []),
    ("/debug/pprof/", "ALTO", []),
    ("/phpinfo.php", "ALTO", ["PHP Version"]),
    ("/info.php", "ALTO", ["PHP Version"]),
    ("/server-info", "ALTO", ["Server Version"]),
    ("/server-status", "MEDIO", []),
    ("/elmah.axd", "ALTO", []),
    ("/trace.axd", "ALTO", []),
    ("/_debugbar/open", "ALTO", []),
    # Database dumps
    ("/backup.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
    ("/backup.zip", "CRITICO", []),
    ("/backup.tar.gz", "CRITICO", []),
    ("/db.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
    ("/database.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
    ("/dump.sql", "CRITICO", ["INSERT", "CREATE TABLE"]),
    ("/data.sql", "CRITICO", ["INSERT"]),
    # Version control
    ("/.git/config", "CRITICO", ["[remote", "[branch"]),
    ("/.git/HEAD", "ALTO", ["ref:"]),
    ("/.git/logs/HEAD", "ALTO", ["commit"]),
    ("/.svn/entries", "ALTO", []),
    ("/.svn/wc.db", "ALTO", []),
    ("/.hg/dirstate", "ALTO", []),
    # Credentials & Keys
    ("/.htpasswd", "CRITICO", [":"]),
    ("/.htaccess", "MEDIO", []),
    ("/id_rsa", "CRITICO", ["PRIVATE KEY"]),
    ("/id_rsa.pub", "MEDIO", ["ssh-rsa"]),
    ("/id_ed25519", "CRITICO", ["PRIVATE KEY"]),
    ("/.ssh/authorized_keys", "ALTO", ["ssh-rsa", "ssh-ed25519"]),
    # Container & CI/CD
    ("/docker-compose.yml", "ALTO", ["services"]),
    ("/docker-compose.yaml", "ALTO", ["services"]),
    ("/Dockerfile", "MEDIO", ["FROM"]),
    ("/.github/workflows/", "MEDIO", []),
    ("/.gitlab-ci.yml", "ALTO", ["script", "deploy"]),
    ("/Jenkinsfile", "ALTO", ["pipeline", "stage"]),
    ("/bitbucket-pipelines.yml", "ALTO", ["pipelines"]),
    ("/.circleci/config.yml", "ALTO", ["jobs"]),
    # Logs
    ("/error.log", "MEDIO", []),
    ("/access.log", "MEDIO", []),
    ("/debug.log", "MEDIO", []),
    ("/app.log", "MEDIO", []),
    ("/laravel.log", "ALTO", ["exception", "stack trace"]),
    ("/npm-debug.log", "BAIXO", []),
    # API docs
    ("/swagger.json", "MEDIO", ["paths", "swagger"]),
    ("/swagger.yaml", "MEDIO", ["paths", "swagger"]),
    ("/openapi.json", "MEDIO", ["openapi"]),
    ("/api-docs", "MEDIO", []),
    ("/v2/api-docs", "MEDIO", []),
    ("/graphql", "MEDIO", []),
    # Actuators (Spring)
    ("/actuator", "ALTO", []),
    ("/actuator/env", "CRITICO", []),
    ("/actuator/health", "MEDIO", []),
    ("/actuator/heapdump", "CRITICO", []),
    ("/actuator/configprops", "CRITICO", []),
    ("/actuator/mappings", "ALTO", []),
    ("/actuator/beans", "ALTO", []),
    # AWS/Cloud
    ("/credentials", "CRITICO", ["aws_access_key", "aws_secret"]),
    ("/.aws/credentials", "CRITICO", ["aws_access_key"]),
    # Package managers
    ("/package.json", "BAIXO", ["dependencies"]),
    ("/composer.json", "BAIXO", ["require"]),
    ("/Gemfile", "BAIXO", ["gem"]),
    ("/requirements.txt", "BAIXO", []),
    # Wordpress
    ("/wp-json/wp/v2/users", "MEDIO", ["slug", "name"]),
    ("/xmlrpc.php", "MEDIO", []),
    ("/readme.html", "BAIXO", []),
]


def _check_response_headers(target):
    """Analisa headers de resposta para information disclosure."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}/", timeout=5)

        # Server header
        server = resp.headers.get("Server", "")
        if server:
            vulns.append({
                "tipo": "SERVER_HEADER_EXPOSED", "valor": server[:80],
                "severidade": "BAIXO",
                "descricao": f"Server header expõe versão: {server[:80]}",
            })

        # X-Powered-By
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            vulns.append({
                "tipo": "X_POWERED_BY", "valor": powered[:80],
                "severidade": "BAIXO",
                "descricao": f"X-Powered-By expõe tecnologia: {powered[:80]}",
            })

        # X-AspNet-Version
        aspnet = resp.headers.get("X-AspNet-Version", "")
        if aspnet:
            vulns.append({
                "tipo": "ASPNET_VERSION", "valor": aspnet,
                "severidade": "BAIXO",
                "descricao": f"ASP.NET version exposed: {aspnet}",
            })

    except Exception:
        pass
    return vulns


def _check_error_pages(target):
    """Analisa error pages para information disclosure."""
    vulns = []
    error_paths = [
        "/doesnotexist" + "".join([str(i) for i in range(5)]),
        "/api/nonexistent",
        "/' OR 1=1",
    ]
    for path in error_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            body = resp.text.lower()

            if "stack trace" in body or "traceback" in body:
                vulns.append({
                    "tipo": "STACK_TRACE_EXPOSED", "path": path,
                    "severidade": "ALTO",
                    "descricao": "Stack trace exposed em error page!",
                })
            if "django" in body or "laravel" in body or "express" in body:
                vulns.append({
                    "tipo": "FRAMEWORK_EXPOSED_IN_ERROR", "path": path,
                    "severidade": "MEDIO",
                    "descricao": "Framework detectado via error page",
                })
            if resp.headers.get("X-Debug-Token"):
                vulns.append({
                    "tipo": "DEBUG_TOKEN_EXPOSED", "path": path,
                    "severidade": "ALTO",
                    "descricao": "Symfony debug token em header!",
                })
        except Exception:
            continue
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner Information Disclosure 2026-Grade — Files, Headers, Errors.

    Técnicas: 80+ sensitive paths (.env/config/backups/git/docker/CI-CD/actuators/
    cloud credentials/package managers/WordPress), response header analysis
    (Server/X-Powered-By/X-AspNet-Version), error page analysis
    (stack trace/framework exposure/debug tokens), Spring Actuator endpoints.
    """
    _ = (ip, open_ports, banners)
    vulns = []

    for path, severidade, indicators in SENSITIVE_PATHS:
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, timeout=4)
            if resp.status_code == 200 and len(resp.text) > 10:
                if indicators:
                    found = [ind for ind in indicators if ind in resp.text]
                    if found:
                        vulns.append({
                            "tipo": "INFO_DISCLOSURE", "path": path,
                            "severidade": severidade, "indicadores": found,
                            "tamanho": len(resp.text),
                        })
                else:
                    vulns.append({
                        "tipo": "FILE_EXPOSED", "path": path,
                        "severidade": severidade, "tamanho": len(resp.text),
                    })
        except Exception:
            continue

    vulns.extend(_check_response_headers(target))
    vulns.extend(_check_error_pages(target))

    return {
        "plugin": "info_disclosure",
        "versao": "2026.1",
        "tecnicas": ["sensitive_files", "env_files", "git_exposure",
                      "actuators", "cloud_credentials", "cicd_files",
                      "header_analysis", "error_page_analysis"],
        "resultados": vulns if vulns else "Nenhuma information disclosure detectada",
    }
