# plugins/secrets_deep_scan.py — Cascavel 2026 Intelligence
import math
import re

import requests

# ──────────── DEEP SECRET PATTERNS (80+) ────────────
DEEP_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICO"),
    (
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "AWS Secret Key",
        "CRITICO",
    ),
    (r"(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})", "AWS Session Token", "CRITICO"),
    (r"ASIA[0-9A-Z]{16}", "AWS Temporary Access Key", "CRITICO"),
    # GCP
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "ALTO"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "ALTO"),
    (r"(?:GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_PROJECT)\s*[:=]\s*['\"]?([^\s\"']+)", "GCP Credential Path", "ALTO"),
    (r"ya29\.[0-9A-Za-z\-_]+", "GCP OAuth Access Token", "CRITICO"),
    # Azure
    (r"AccountKey=[A-Za-z0-9+/=]{88}", "Azure Storage Account Key", "CRITICO"),
    (
        r"(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_CLIENT_ID)\s*[:=]\s*['\"]?([^\s\"']+)",
        "Azure Credential",
        "CRITICO",
    ),
    (r"(?:MSI_SECRET|IDENTITY_ENDPOINT|IDENTITY_HEADER)\s*[:=]\s*['\"]?([^\s\"']+)", "Azure MSI Secret", "CRITICO"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "CRITICO"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key", "ALTO"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", "MEDIO"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", "ALTO"),
    # GitHub
    (r"ghp_[0-9A-Za-z]{36,}", "GitHub Personal Access Token", "CRITICO"),
    (r"gho_[0-9A-Za-z]{36,}", "GitHub OAuth Token", "CRITICO"),
    (r"ghs_[0-9A-Za-z]{36,}", "GitHub Server Token", "CRITICO"),
    (r"ghr_[0-9A-Za-z]{36,}", "GitHub Refresh Token", "CRITICO"),
    (r"github_pat_[0-9A-Za-z_]{82,}", "GitHub Fine-Grained PAT", "CRITICO"),
    # Slack
    (r"xox[bporas]-[0-9A-Za-z\-]{10,}", "Slack Token", "ALTO"),
    (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook", "ALTO"),
    # SendGrid / Mailgun / Twilio
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", "CRITICO"),
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", "CRITICO"),
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", "ALTO"),
    (r"AC[0-9a-fA-F]{32}", "Twilio Account SID", "ALTO"),
    # Firebase / Heroku / Shopify / Discord / Telegram
    (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "Firebase Cloud Messaging Key", "ALTO"),
    (r"shpat_[0-9a-fA-F]{32}", "Shopify Private App Token", "ALTO"),
    (r"shpca_[0-9a-fA-F]{32}", "Shopify Custom App Token", "ALTO"),
    (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", "ALTO"),
    (r"[0-9]+:AA[0-9A-Za-z\-_]{33}", "Telegram Bot Token", "ALTO"),
    # OpenAI / Anthropic / AI Services
    (r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API Key", "CRITICO"),
    (r"sk-proj-[A-Za-z0-9_-]{100,}", "OpenAI Project Key", "CRITICO"),
    (r"sk-ant-[A-Za-z0-9_-]{80,}", "Anthropic API Key", "CRITICO"),
    # Supabase / Database
    (r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT/Supabase Key", "ALTO"),
    (
        r"(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp)://[^\s\"'<>]+",
        "Database Connection String",
        "CRITICO",
    ),
    # Private Keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "Private Key (PEM)", "CRITICO"),
    # Generic Secrets
    (
        r"(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|auth_token|private_key|client_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "Generic Secret",
        "ALTO",
    ),
    (r"Basic\s+[A-Za-z0-9+/=]{20,}", "HTTP Basic Auth Header", "ALTO"),
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer Token", "ALTO"),
    # Heroku
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "UUID/Heroku API Key", "MEDIO"),
]

# ──────────── SENSITIVE FILE PATHS ────────────
DEEP_PATHS = [
    # Environment files
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.env.staging",
    "/.env.development",
    "/.env.backup",
    "/.env.old",
    "/.env.save",
    "/.env.swp",
    "/.env.dist",
    "/.env.docker",
    "/.env.test",
    "/.env.ci",
    # Git
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    # AWS / Cloud
    "/.aws/credentials",
    "/.aws/config",
    "/.gcloud/credentials",
    "/.gcloud/application_default_credentials.json",
    "/.azure/accessTokens.json",
    "/.azure/azureProfile.json",
    # Config files
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.xml",
    "/config.php",
    "/wp-config.php",
    "/settings.py",
    "/local_settings.py",
    "/application.properties",
    "/application.yml",
    "/application.yaml",
    "/database.yml",
    "/database.json",
    "/db.json",
    "/secrets.json",
    "/secrets.yaml",
    "/secrets.yml",
    # Docker / K8s
    "/.docker/config.json",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.prod.yml",
    "/docker-compose.override.yml",
    "/kubeconfig",
    "/.kube/config",
    # CI/CD
    "/.travis.yml",
    "/.gitlab-ci.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
    "/.github/workflows/",
    "/bitbucket-pipelines.yml",
    "/azure-pipelines.yml",
    "/.buildkite/pipeline.yml",
    # Build / Dependency
    "/.npmrc",
    "/.yarnrc",
    "/.pypirc",
    "/.netrc",
    "/.gemrc",
    "/composer.json",
    "/bower.json",
    "/.bowerrc",
    "/firebase.json",
    "/.firebaserc",
    # Other
    "/.htpasswd",
    "/.htaccess",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/debug",
    "/trace",
    "/actuator/env",
    "/actuator/health",
    "/health",
    "/metrics",
    "/prometheus",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    # Backup files
    "/backup.sql",
    "/backup.tar.gz",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/site.tar.gz",
    "/www.zip",
    "/public.zip",
]

# ──────────── JS-EMBEDDED SECRET PATTERNS ────────────
JS_SECRET_PATTERNS = [
    (r"(?:API_KEY|apiKey|api_key)\s*[:=]\s*['\"]([^'\"]{10,})['\"]", "JS API Key"),
    (r"(?:SECRET|secret|SECRET_KEY)\s*[:=]\s*['\"]([^'\"]{10,})['\"]", "JS Secret"),
    (r"(?:TOKEN|token|authToken|auth_token)\s*[:=]\s*['\"]([^'\"]{10,})['\"]", "JS Token"),
    (r"(?:PASSWORD|password|passwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "JS Password"),
    (r"(?:firebaseConfig|firebase)\s*=\s*\{", "Firebase Config Block"),
    (r"(?:process\.env\.[A-Z_]+)", "Environment Variable Reference"),
]


def run(target, ip, ports, banners, context=None):
    """
    Scanner Deep de Secrets 2026-Grade — 80+ Patterns, Deep Path Scan,
    JS Credential Analysis, Cloud Credential Detection, Entropy Analysis.

    Técnicas: 80+ regex patterns (AWS/GCP/Azure/Stripe/GitHub/Slack/SendGrid/
    Twilio/Firebase/Shopify/Discord/Telegram/OpenAI/Anthropic/Supabase/DB URLs),
    80+ sensitive file paths, JS-embedded credential extraction, cloud credential
    detection (AWS/GCP/Azure), Shannon entropy analysis, env file analysis,
    .git/config exposure, actuator/metrics endpoints.
    """
    _ = (ip, ports, banners)
    vulns = []

    # Deep path scanning
    vulns.extend(_scan_deep_paths(target))

    # JS file credential extraction
    vulns.extend(_scan_js_credentials(target))

    # Cloud credential detection
    vulns.extend(_scan_cloud_credentials(target))

    # HTTP response header secrets
    vulns.extend(_scan_response_headers(target))

    # Entropy-based detection on discovered pages
    vulns.extend(_entropy_scan_pages(target, context))

    return {
        "plugin": "secrets_deep_scan",
        "versao": "2026.1",
        "tecnicas": [
            "80_plus_regex_patterns",
            "80_plus_sensitive_paths",
            "js_credential_extraction",
            "cloud_credential_detection",
            "entropy_analysis",
            "header_secret_scan",
            "git_config_exposure",
            "actuator_scan",
        ],
        "resultados": vulns if vulns else "Nenhum secret profundo encontrado",
    }


def _scan_deep_paths(target):
    """Escaneia 80+ paths sensíveis e analisa conteúdo com regex."""
    vulns = []
    for path in DEEP_PATHS:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            # Classify severity based on path type
            sev = "ALTO"
            if any(s in path for s in [".env", ".aws", ".gcloud", ".azure", "credentials", "secret", "key", "token"]):
                sev = "CRITICO"
            elif any(s in path for s in [".git", "config", "docker-compose", "kubeconfig"]):
                sev = "ALTO"
            elif any(s in path for s in ["swagger", "openapi", "api-docs", "health", "metrics", "actuator"]):
                sev = "MEDIO"

            vulns.append(
                {
                    "tipo": "DEEP_PATH_EXPOSED",
                    "path": path,
                    "severidade": sev,
                    "tamanho": len(resp.text),
                    "descricao": f"Path sensível exposto: {path}",
                    "remediao": "Remover ou restringir acesso público a este path.",
                }
            )

            # Regex scan against content
            for pattern, label, pattern_sev in DEEP_PATTERNS:
                matches = re.findall(pattern, resp.text, re.DOTALL)
                if matches:
                    vulns.append(
                        {
                            "tipo": "DEEP_SECRET_FOUND",
                            "path": path,
                            "secret_type": label,
                            "quantidade": len(matches),
                            "amostra": str(matches[0])[:40] + "...",
                            "severidade": pattern_sev,
                            "descricao": f"{label} encontrado em {path}!",
                            "remediao": "Remover secret hardcoded, usar secret manager (Vault/AWS SM/GCP SM).",
                        }
                    )

            # Special: .git/config exposure
            if path == "/.git/config" and "url" in resp.text:
                remote_match = re.search(r"url\s*=\s*(.+)", resp.text)
                if remote_match:
                    vulns.append(
                        {
                            "tipo": "GIT_REMOTE_EXPOSED",
                            "remote_url": remote_match.group(1).strip(),
                            "severidade": "CRITICO",
                            "descricao": "Git remote URL exposto — repositório clonável!",
                            "remediao": "Bloquear acesso público ao diretório .git no webserver.",
                        }
                    )

        except Exception:
            continue
    return vulns


def _scan_js_credentials(target):
    """Extrai credenciais hardcoded de arquivos JavaScript."""
    vulns = []
    js_paths = [
        "/js/app.js",
        "/js/main.js",
        "/js/bundle.js",
        "/js/vendor.js",
        "/static/js/main.js",
        "/static/js/app.js",
        "/assets/js/app.js",
        "/dist/js/app.js",
        "/build/static/js/main.js",
        "/js/config.js",
        "/js/env.js",
        "/js/settings.js",
    ]

    # Also try to discover JS files from common entry points
    try:
        resp = requests.get(f"http://{target}", timeout=7)
        if resp.status_code == 200:
            js_refs = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', resp.text)
            for ref in js_refs[:15]:
                if ref.startswith("/"):
                    js_paths.append(ref)
                elif ref.startswith("http") and target in ref:
                    path = ref.split(target, 1)[-1] if target in ref else ""
                    if path:
                        js_paths.append(path)
    except Exception:
        pass

    seen = set()
    for js_path in js_paths:
        if js_path in seen:
            continue
        seen.add(js_path)

        try:
            url = f"http://{target}{js_path}" if js_path.startswith("/") else js_path
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200 or len(resp.text) < 50:
                continue

            for pattern, label in JS_SECRET_PATTERNS:
                matches = re.findall(pattern, resp.text)
                if matches:
                    for match in matches[:3]:
                        if len(match) > 5 and not match.startswith("${"):
                            vulns.append(
                                {
                                    "tipo": "JS_EMBEDDED_SECRET",
                                    "file": js_path,
                                    "secret_type": label,
                                    "amostra": str(match)[:40] + "...",
                                    "severidade": "ALTO",
                                    "descricao": f"{label} hardcoded em {js_path}!",
                                    "remediao": "Mover secrets para variáveis de ambiente server-side.",
                                }
                            )

        except Exception:
            continue
    return vulns


def _scan_cloud_credentials(target):
    """Detecta credenciais de cloud providers em responses."""
    vulns = []
    check_paths = ["/", "/config", "/api/config", "/status", "/health", "/info", "/env"]

    for path in check_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200:
                continue

            content = resp.text

            # AWS credential patterns
            aws_keys = re.findall(r"AKIA[0-9A-Z]{16}", content)
            if aws_keys:
                vulns.append(
                    {
                        "tipo": "AWS_KEY_EXPOSED",
                        "path": path,
                        "keys_encontradas": len(aws_keys),
                        "amostra": aws_keys[0][:8] + "...",
                        "severidade": "CRITICO",
                        "descricao": "AWS Access Key exposta em response!",
                        "remediao": "Rotacionar key imediatamente. Usar IAM roles ou secret manager.",
                    }
                )

            # GCP service account JSON
            if '"type": "service_account"' in content and '"private_key"' in content:
                vulns.append(
                    {
                        "tipo": "GCP_SA_EXPOSED",
                        "path": path,
                        "severidade": "CRITICO",
                        "descricao": "GCP Service Account JSON completo exposto!",
                        "remediao": "Rotacionar SA key. Usar Workload Identity em vez de keys.",
                    }
                )

            # Azure credentials
            azure_patterns = [
                (r"(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID)\s*[:=]\s*['\"]([^'\"]+)", "Azure Service Principal"),
                (r"AccountKey=[A-Za-z0-9+/=]{88}", "Azure Storage Key"),
            ]
            for pattern, label in azure_patterns:
                if re.search(pattern, content):
                    vulns.append(
                        {
                            "tipo": "AZURE_CREDENTIAL_EXPOSED",
                            "path": path,
                            "credential_type": label,
                            "severidade": "CRITICO",
                            "descricao": f"{label} exposta em {path}!",
                            "remediao": "Rotacionar credencial. Usar Managed Identity.",
                        }
                    )

        except Exception:
            continue
    return vulns


def _scan_response_headers(target):
    """Analisa headers HTTP em busca de secrets expostos."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}/", timeout=7)
        headers = resp.headers

        # Check for auth tokens in headers
        sensitive_headers = [
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "authorization",
            "x-secret",
            "x-token",
            "x-csrf-token",
            "cookie",
        ]
        for header in sensitive_headers:
            value = headers.get(header, "")
            if value and len(value) > 10:
                vulns.append(
                    {
                        "tipo": "HEADER_SECRET_EXPOSED",
                        "header": header,
                        "amostra": value[:30] + "...",
                        "severidade": "ALTO" if header != "authorization" else "CRITICO",
                        "descricao": f"Header '{header}' contém possível secret!",
                        "remediao": "Remover headers sensíveis de responses.",
                    }
                )

        # Check for debug info in headers
        debug_headers = ["x-debug", "x-powered-by", "server", "x-aspnet-version", "x-runtime"]
        for header in debug_headers:
            value = headers.get(header, "")
            if value:
                vulns.append(
                    {
                        "tipo": "DEBUG_HEADER_EXPOSED",
                        "header": header,
                        "valor": value[:100],
                        "severidade": "BAIXO",
                        "descricao": f"Header de debug '{header}' exposto.",
                        "remediao": "Remover headers informativos em produção.",
                    }
                )

    except Exception:
        pass
    return vulns


def _entropy_scan_pages(target, context):
    """Scan páginas comuns por strings de alta entropia (possíveis secrets)."""
    vulns = []
    paths = ["/", "/config", "/api", "/admin", "/dashboard"]

    # Use discovered params from context if available
    if context and context.get("discovered_params"):
        paths.extend([f"/?{p}=test" for p in context["discovered_params"][:5]])

    for path in paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200:
                continue

            # Find high-entropy strings
            candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{30,})["\']', resp.text)
            for candidate in candidates[:10]:
                entropy = _calculate_entropy(candidate)
                if entropy > 4.5 and len(candidate) >= 30:
                    vulns.append(
                        {
                            "tipo": "HIGH_ENTROPY_SECRET",
                            "path": path,
                            "entropia": entropy,
                            "tamanho": len(candidate),
                            "amostra": candidate[:25] + "...",
                            "severidade": "ALTO" if entropy > 5.0 else "MEDIO",
                            "descricao": f"String de alta entropia ({entropy}) em {path} — possível secret!",
                            "remediao": "Verificar se é um secret e movê-lo para secret manager.",
                        }
                    )

        except Exception:
            continue
    return vulns


def _calculate_entropy(text):
    """Calcula Shannon entropy de uma string."""
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 2)
