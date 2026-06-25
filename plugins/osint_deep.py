# plugins/osint_deep.py — Cascavel 2026 Intelligence

import requests

# Social media / profile endpoints to check
SOCIAL_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/humans.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

# Code repository indicators
REPO_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/dirstate",
    "/.hg/requires",
    "/.bzr/branch-format",
    "/CVS/Root",
    "/CVS/Repository",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/.dockerignore",
    "/Makefile",
    "/Rakefile",
    "/Gemfile",
    "/package.json",
    "/composer.json",
    "/pom.xml",
    "/build.gradle",
    "/.travis.yml",
    "/.github/workflows/",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/.gitlab-ci.yml",
    "/bitbucket-pipelines.yml",
    "/vercel.json",
    "/netlify.toml",
    "/firebase.json",
    "/serverless.yml",
    "/terraform.tf",
    "/main.tf",
]

# Documentation paths
DOC_PATHS = [
    "/docs",
    "/documentation",
    "/api-docs",
    "/wiki",
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/redoc",
    "/swagger-ui/",
    "/graphql",
    "/postman/collection.json",
    "/insomnia.json",
    "/CHANGELOG.md",
    "/README.md",
    "/CONTRIBUTING.md",
    "/SECURITY.md",
    "/LICENSE",
    "/admin",
    "/admin/docs",
    "/internal",
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/trace",
    "/metrics",
    "/health",
]

# Common subdomains for domain squatting check
SQUAT_PATTERNS = [
    "{base}secure.com",
    "{base}login.com",
    "{base}auth.com",
    "{base}-app.com",
    "{base}-api.com",
    "{base}-dev.com",
    "{base}support.com",
    "{base}help.com",
    "{base}portal.com",
    "{base}mail.com",
    "{base}-mail.com",
    "{base}web.com",
    "{base}online.com",
    "{base}net.com",
    "{base}org.com",
    "my{base}.com",
    "get{base}.com",
    "{base}hq.com",
    "{base}-inc.com",
    "{base}.co",
    "{base}.io",
]

# GitHub dork queries
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" credentials',
    '"{domain}" AWS_SECRET',
    '"{domain}" PRIVATE_KEY',
    '"{domain}" jdbc:',
]


def _check_social_profiles(target):
    """Check for exposed social media profiles and OSINT sources."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Check security.txt
    try:
        resp = requests.get(f"https://{clean}/.well-known/security.txt", timeout=5, verify=False)
        if resp.status_code == 200 and "contact" in resp.text.lower():
            findings.append(
                {
                    "tipo": "SECURITY_TXT",
                    "url": f"https://{clean}/.well-known/security.txt",
                    "severidade": "INFO",
                    "descricao": "security.txt encontrado — contém informações de contato do security team",
                    "preview": resp.text[:300],
                    "remediacao": "Verificar se as informações de contato estão atualizadas.",
                }
            )
    except Exception:  # noqa: S110
        pass

    # Check robots.txt for sensitive paths
    try:
        resp = requests.get(f"https://{clean}/robots.txt", timeout=5, verify=False)
        if resp.status_code == 200:
            sensitive = []
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and any(
                        kw in path.lower()
                        for kw in [
                            "admin",
                            "private",
                            "secret",
                            "internal",
                            "api",
                            "config",
                            "backup",
                            "debug",
                            "test",
                            "staging",
                        ]
                    ):
                        sensitive.append(path)
            if sensitive:
                findings.append(
                    {
                        "tipo": "ROBOTS_SENSITIVE",
                        "paths": sensitive,
                        "severidade": "MEDIO",
                        "descricao": f"robots.txt revela {len(sensitive)} paths sensíveis",
                        "remediacao": "Remover paths sensíveis do robots.txt. Usar autenticação em vez de security by obscurity.",
                    }
                )
    except Exception:  # noqa: S110
        pass

    # Check for social links in page source
    try:
        resp = requests.get(f"https://{clean}/", timeout=5, verify=False)
        if resp.status_code == 200:
            body = resp.text.lower()
            social = []
            for platform in [
                "github.com",
                "gitlab.com",
                "bitbucket.org",
                "twitter.com",
                "linkedin.com",
                "facebook.com",
                "instagram.com",
                "youtube.com",
            ]:
                if platform in body:
                    social.append(platform)
            if social:
                findings.append(
                    {
                        "tipo": "SOCIAL_PRESENCE",
                        "plataformas": social,
                        "severidade": "INFO",
                        "descricao": f"Presença social detectada: {', '.join(social)}",
                        "remediacao": "Auditar perfis sociais para informações sensíveis expostas.",
                    }
                )
    except Exception:  # noqa: S110
        pass

    # Check for exposed profiles via API
    for path in SOCIAL_PATHS:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.text) > 30:
                findings.append(
                    {
                        "tipo": "OSINT_SOURCE",
                        "path": path,
                        "status": resp.status_code,
                        "severidade": "INFO",
                        "descricao": f"Fonte OSINT encontrada: {path}",
                        "preview": resp.text[:200],
                    }
                )
        except Exception:
            continue

    return findings


def _check_leaked_credentials(target):
    """Check for leaked credentials indicators."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Check for exposed .env files
    env_paths = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.staging",
        "/.env.backup",
        "/.env.old",
        "/env",
        "/environment",
        "/config/.env",
        "/app/.env",
        "/src/.env",
    ]
    for path in env_paths:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text
                if any(
                    kw in body.upper()
                    for kw in [
                        "KEY",
                        "SECRET",
                        "TOKEN",
                        "PASSWORD",
                        "DATABASE_URL",
                        "AWS_",
                        "API_KEY",
                        "PRIVATE_KEY",
                        "SMTP_",
                    ]
                ):
                    findings.append(
                        {
                            "tipo": "LEAKED_ENV",
                            "path": path,
                            "severidade": "CRITICO",
                            "descricao": f"Arquivo .env exposto em {path} — credenciais possivelmente comprometidas",
                            "preview": body[:200],
                            "remediacao": "Remover imediatamente. Rotacionar todas as credenciais. Bloquear acesso via webserver.",
                        }
                    )
        except Exception:
            continue

    # Check for exposed backup files
    backup_paths = [
        "/backup.sql",
        "/dump.sql",
        "/db.sql",
        "/database.sql",
        "/backup.tar.gz",
        "/backup.zip",
        "/site.zip",
        "/www.zip",
        "/backup.bak",
        "/config.bak",
        "/.bak",
    ]
    for path in backup_paths:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 100:
                findings.append(
                    {
                        "tipo": "BACKUP_EXPOSED",
                        "path": path,
                        "tamanho": len(resp.content),
                        "severidade": "CRITICO",
                        "descricao": f"Backup exposto em {path} ({len(resp.content)} bytes) — pode conter credenciais",
                        "remediacao": "Remover imediatamente. Verificar se backup foi acessado por terceiros.",
                    }
                )
        except Exception:
            continue

    return findings


def _check_code_repositories(target):
    """Check for exposed code repositories."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    for path in REPO_PATHS:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                severity = "ALTO"
                if any(kw in path for kw in [".env", ".git/config", ".svn", ".hg"]):
                    severity = "CRITICO"
                elif any(kw in path for kw in ["docker-compose", "Dockerfile", "Jenkinsfile"]):
                    severity = "MEDIO"

                finding = {
                    "tipo": "REPO_EXPOSED",
                    "path": path,
                    "status": resp.status_code,
                    "severidade": severity,
                    "descricao": f"Repositório/arquivo de código exposto: {path}",
                    "remediacao": "Remover acesso público. Configurar .htaccess/nginx para bloquear paths sensíveis.",
                }

                # Check for secrets in the content
                body = resp.text.lower()
                if any(kw in body for kw in ["password", "secret", "key", "token", "credential"]):
                    finding["severidade"] = "CRITICO"
                    finding["descricao"] += " — POSSÍVEL VAZAMENTO DE CREDENCIAIS"
                    finding["preview"] = resp.text[:200]

                findings.append(finding)
        except Exception:
            continue

    return findings


def _check_domain_squatting(target):
    """Check for domain squatting / typosquatting."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    base_domain = clean.split(":")[0]

    # Extract base name (remove TLD)
    parts = base_domain.split(".")
    if len(parts) >= 2:
        base_name = parts[-2]  # e.g., "example" from "example.com"
        squat_domains = []
        for pattern in SQUAT_PATTERNS:
            domain = pattern.format(base=base_name)
            try:
                import socket

                socket.gethostbyname(domain)
                squat_domains.append(domain)
            except socket.gaierror:
                continue
            except Exception:
                continue

        if squat_domains:
            findings.append(
                {
                    "tipo": "DOMAIN_SQUATTING",
                    "dominios": squat_domains,
                    "severidade": "ALTO",
                    "descricao": f"{len(squat_domains)} domínios squatting ativos detectados",
                    "remediacao": "Registrar domínios similares defensivamente. Monitorar novos registros. Implementar DMARC.",
                }
            )

        # Check for homograph attacks (IDN)
        # Just flag the possibility
        findings.append(
            {
                "tipo": "HOMOGRAPH_CHECK",
                "severidade": "INFO",
                "descricao": "Verificar manualmente ataques homograph/IDN com caracteres Unicode similares",
                "remediacao": "Monitorar certificados CT logs para domínios IDN similares.",
            }
        )

    return findings


def _check_exposed_docs(target):
    """Check for exposed documentation and debug interfaces."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    for path in DOC_PATHS:
        try:
            resp = requests.get(f"https://{clean}{path}", timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                severity = "MEDIO"
                if any(kw in path for kw in ["debug", "pprof", "trace", "internal"]):
                    severity = "CRITICO"
                elif any(kw in path for kw in ["swagger", "openapi", "graphql"]):
                    severity = "ALTO"
                elif any(kw in path for kw in ["admin", "internal"]):
                    severity = "ALTO"

                findings.append(
                    {
                        "tipo": "DOCS_EXPOSED",
                        "path": path,
                        "status": resp.status_code,
                        "severidade": severity,
                        "descricao": f"Documentação exposta: {path}",
                        "preview": resp.text[:200],
                        "remediacao": "Restringir acesso a documentação. Usar autenticação ou IP whitelist.",
                    }
                )
        except Exception:
            continue

    return findings


def _check_github_dorks(target):
    """Check for GitHub dork results (passive, no API key needed)."""
    findings = []
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    base_domain = clean.split(":")[0]

    # Note: GitHub search API requires auth for higher rate limits
    # This performs passive checks only
    search_url = "https://api.github.com/search/code"
    for dork in GITHUB_DORKS[:3]:  # Limit to avoid rate limiting
        query = dork.format(domain=base_domain)
        try:
            resp = requests.get(
                search_url,
                params={"q": query, "per_page": 5},
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("total_count", 0) > 0:
                    findings.append(
                        {
                            "tipo": "GITHUB_LEAK",
                            "query": query,
                            "total": data["total_count"],
                            "severidade": "ALTO",
                            "descricao": f"GitHub search encontrou {data['total_count']} resultados para: {query}",
                            "remediacao": "Auditar repositórios encontrados. Rotacionar credenciais expostas. Implementar secret scanning.",
                            "amostra": [
                                {"repo": item.get("repository", {}).get("full_name", ""), "file": item.get("path", "")}
                                for item in data.get("items", [])[:3]
                            ],
                        }
                    )
        except Exception:
            continue

    return findings


def run(target, ip, open_ports, banners, context=None):
    """
    OSINT Deep 2026-Grade — Social Profiles, Leaked Credentials, Code Repos, Domain Squatting.

    Técnicas: social media presence detection, leaked .env/backup files,
    exposed code repositories (.git/.svn/.hg), domain squatting/typosquatting,
    exposed documentation/debug interfaces, GitHub dorking passivo.
    """
    _ = (ip, open_ports, banners)
    resultado = {
        "social_profiles": [],
        "leaked_credentials": [],
        "code_repositories": [],
        "domain_squatting": [],
        "exposed_docs": [],
        "github_leaks": [],
    }

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    resultado["social_profiles"] = _check_social_profiles(clean_target)
    resultado["leaked_credentials"] = _check_leaked_credentials(clean_target)
    resultado["code_repositories"] = _check_code_repositories(clean_target)
    resultado["domain_squatting"] = _check_domain_squatting(clean_target)
    resultado["exposed_docs"] = _check_exposed_docs(clean_target)
    resultado["github_leaks"] = _check_github_dorks(clean_target)

    total = sum(len(v) for v in resultado.values() if isinstance(v, list))
    critico = sum(
        1
        for v in resultado.values()
        if isinstance(v, list)
        for f in v
        if isinstance(f, dict) and f.get("severidade") == "CRITICO"
    )

    resultado["resumo"] = {
        "total_achados": total,
        "criticos": critico,
        "status": "VULNERAVEL" if critico > 0 else ("ATENCAO" if total > 0 else "LIMPO"),
    }

    return {
        "plugin": "osint_deep",
        "versao": "2026.1",
        "tecnicas": [
            "social_profile_detection",
            "leaked_credentials",
            "exposed_repositories",
            "domain_squatting",
            "docs_exposure",
            "github_dorking",
        ],
        "resultados": resultado,
    }
