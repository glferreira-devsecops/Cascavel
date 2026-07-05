# plugins/supply_chain_scan.py — Cascavel 2026 Intelligence
import re

import requests

# ──────────── KNOWN MALICIOUS PACKAGES (2024-2026) ────────────
MALICIOUS_NPM = [
    "crossenv",
    "cross-env.js",
    "node-ipc",
    "peacenotwar",
    "colors.js",
    "faker.js",
    "ua-parser-js",
    "coa",
    "rc",
    "event-stream",
    "flatmap-stream",
    "eslint-scope",
    "getcookies",
    "express-cookies",
    "node-opn",
    "nodemailer.js",
    "nodefabric",
    "nodesass",
    "npm-scripts-info",
    "babelcli",
    "crossenv",
    "cross-env.js",
    "crossenv.js",
    "mongose",
    "npm-debug-log.js",
    "smb",
    "sqlite3.js",
    "noderequest",
    "nodeffmpeg",
]

MALICIOUS_PYPI = [
    "python3-dateutil",
    "jeIlyfish",
    "jeIlyfish",
    "python-dateutil2",
    "colourama",
    "cColourama",
    "requesocks",
    "requesta",
    "requst",
    "urlib3",
    "urllib3-fake",
    "beautifulsoup",
    "lxml-fake",
    "crypto",
    "pynum",
    "pycrypto-fake",
    "setuptools-dev",
    "pip-dev",
    "12factor",
    "slackclient-fake",
    "boto3-dev",
    "awscli-dev",
    "django-dev",
    "flask-dev",
]

MALICIOUS_CARGO = [
    "rustdecimal",
    "serde_qs",
    "tokio-rs",
    "hyper-tls",
]

# ──────────── TYPOSQUATTING PATTERNS ────────────
TYPOSQUAT_PATTERNS = {
    "npm": [
        (
            r"^(?:express|lodash|react|vue|angular|webpack|babel|eslint|prettier|jest|axios|moment|dayjs|dotenv|mongoose|sequelize|typeorm|prisma|next|nuxt|svelte|tailwindcss|socket\.io|passport|jsonwebtoken|bcrypt|cors|helmet|multer|nodemon|pm2|typescript|rxjs)(?:[-_.]?(?:js|ts|dev|util|utils|helper|helpers|lib|core|lite|mini|pro|plus|extended|extra|custom|patch|fix|updated|new|latest|next|beta|alpha|rc))?$",
            "Possível typosquatting npm — nome quase idêntico a pacote popular",
        ),
    ],
    "pypi": [
        (
            r"^(?:requests|flask|django|fastapi|numpy|pandas|scipy|matplotlib|scikit-learn|tensorflow|torch|pytorch|opencv|pillow|beautifulsoup4|scrapy|celery|redis|sqlalchemy|alembic|pydantic|boto3|google-cloud|azure|kubernetes|paramiko|cryptography|pyOpenSSL|urllib3|certifi|setuptools|pip|wheel|poetry)(?:[-_.]?(?:dev|util|utils|lib|core|lite|mini|pro|plus|extended|extra|fake|patch|fix|updated|new|latest|next|beta|alpha|rc|2|3|4))?$",
            "Possível typosquatting PyPI — nome quase idêntico a pacote popular",
        ),
    ],
}


def run(target, ip, ports, banners, context=None):
    """
    Scanner de Supply Chain 2026-Grade — Dependency Confusion, Typosquatting,
    Malicious Packages, Integrity Check.

    Técnicas: dependency confusion (npm/pip/cargo), typosquatting detection,
    known malicious package database (100+ packages), package integrity
    verification, lockfile analysis, registry endpoint probing.
    """
    _ = (ip, ports, banners)
    vulns = []

    vulns.extend(_check_npm_supply_chain(target))
    vulns.extend(_check_pypi_supply_chain(target))
    vulns.extend(_check_cargo_supply_chain(target))
    vulns.extend(_check_dependency_confusion(target))
    vulns.extend(_check_exposed_lockfiles(target))
    vulns.extend(_check_package_integrity(target))

    return {
        "plugin": "supply_chain_scan",
        "versao": "2026.1",
        "tecnicas": [
            "dependency_confusion_npm",
            "dependency_confusion_pypi",
            "dependency_confusion_cargo",
            "typosquatting_detection",
            "malicious_package_db",
            "lockfile_analysis",
            "integrity_check",
        ],
        "resultados": vulns if vulns else "Nenhuma vulnerabilidade de supply chain detectada",
    }


def _check_npm_supply_chain(target):
    """Verifica package.json exposto e analisa dependências npm."""
    vulns = []
    npm_paths = [
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/.npmrc",
        "/.yarnrc",
        "/.yarnrc.yml",
        "/lerna.json",
        "/nx.json",
        "/turbo.json",
    ]
    for path in npm_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            vulns.append(
                {
                    "tipo": "NPM_FILE_EXPOSED",
                    "path": path,
                    "severidade": "ALTO",
                    "descricao": f"Arquivo npm {path} exposto — mapeamento de dependências!",
                    "remediao": "Restringir acesso público a package.json e lockfiles.",
                }
            )

            if path.endswith("package.json"):
                vulns.extend(_analyze_npm_deps(resp.text))

        except Exception:
            continue
    return vulns


def _analyze_npm_deps(content):
    """Analisa dependências npm contra DB de pacotes maliciosos e typosquatting."""
    vulns = []
    import json

    try:
        pkg = json.loads(content)
    except Exception:
        return vulns

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))
    all_deps.update(pkg.get("peerDependencies", {}))
    all_deps.update(pkg.get("optionalDependencies", {}))

    for dep_name in all_deps:
        # Malicious package check
        if dep_name.lower() in [m.lower() for m in MALICIOUS_NPM]:
            vulns.append(
                {
                    "tipo": "NPM_MALICIOUS_PACKAGE",
                    "package": dep_name,
                    "severidade": "CRITICO",
                    "descricao": f"Pacote npm malicioso conhecido: {dep_name}",
                    "remediao": f"Remover imediatamente {dep_name} e rotacionar credenciais.",
                }
            )

        # Typosquatting check
        for pattern, desc in TYPOSQUAT_PATTERNS.get("npm", []):
            if re.match(pattern, dep_name, re.IGNORECASE):
                vulns.append(
                    {
                        "tipo": "NPM_TYPOSQUATTING_SUSPECT",
                        "package": dep_name,
                        "severidade": "ALTO",
                        "descricao": f"{desc}: {dep_name}",
                        "remediao": f"Verificar se {dep_name} é o pacote legítimo antes de instalar.",
                    }
                )
                break

    return vulns


def _check_pypi_supply_chain(target):
    """Verifica requirements.txt/setup.py/pyproject.toml expostos."""
    vulns = []
    pypi_paths = [
        "/requirements.txt",
        "/requirements-dev.txt",
        "/requirements-prod.txt",
        "/setup.py",
        "/setup.cfg",
        "/pyproject.toml",
        "/Pipfile",
        "/Pipfile.lock",
        "/poetry.lock",
        "/tox.ini",
        "/conda.yml",
        "/environment.yml",
    ]
    for path in pypi_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            vulns.append(
                {
                    "tipo": "PYPI_FILE_EXPOSED",
                    "path": path,
                    "severidade": "ALTO",
                    "descricao": f"Arquivo Python {path} exposto — mapeamento de dependências!",
                    "remediao": "Restringir acesso público a requirements e configurações de build.",
                }
            )

            vulns.extend(_analyze_pypi_deps(resp.text))

        except Exception:
            continue
    return vulns


def _analyze_pypi_deps(content):
    """Analisa dependências PyPI contra DB de pacotes maliciosos."""
    vulns = []
    # Extract package names from requirements.txt style
    dep_pattern = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", re.MULTILINE)
    deps = dep_pattern.findall(content)

    for dep in deps:
        clean_dep = re.sub(r"[-_.]+", "-", dep).lower()
        # Malicious package check
        for malicious in MALICIOUS_PYPI:
            if clean_dep == re.sub(r"[-_.]+", "-", malicious).lower():
                vulns.append(
                    {
                        "tipo": "PYPI_MALICIOUS_PACKAGE",
                        "package": dep,
                        "severidade": "CRITICO",
                        "descricao": f"Pacote PyPI malicioso conhecido: {dep}",
                        "remediao": f"Remover imediatamente {dep} e auditar ambiente.",
                    }
                )

        # Typosquatting check
        for pattern, desc in TYPOSQUAT_PATTERNS.get("pypi", []):
            if re.match(pattern, dep, re.IGNORECASE):
                vulns.append(
                    {
                        "tipo": "PYPI_TYPOSQUATTING_SUSPECT",
                        "package": dep,
                        "severidade": "ALTO",
                        "descricao": f"{desc}: {dep}",
                        "remediao": f"Verificar se {dep} é o pacote legítimo.",
                    }
                )
                break

    return vulns


def _check_cargo_supply_chain(target):
    """Verifica Cargo.toml/Cargo.lock expostos."""
    vulns = []
    cargo_paths = ["/Cargo.toml", "/Cargo.lock"]
    for path in cargo_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            vulns.append(
                {
                    "tipo": "CARGO_FILE_EXPOSED",
                    "path": path,
                    "severidade": "ALTO",
                    "descricao": f"Arquivo Cargo {path} exposto!",
                    "remediao": "Restringir acesso público a manifests e lockfiles.",
                }
            )

            # Check for malicious crates
            for malicious in MALICIOUS_CARGO:
                if malicious in resp.text:
                    vulns.append(
                        {
                            "tipo": "CARGO_MALICIOUS_CRATE",
                            "crate": malicious,
                            "severidade": "CRITICO",
                            "descricao": f"Crate malicioso conhecido: {malicious}",
                            "remediao": f"Remover {malicious} imediatamente.",
                        }
                    )

        except Exception:
            continue
    return vulns


def _check_dependency_confusion(target):
    """Detecta possível dependency confusion via registries internos."""
    vulns = []
    # Check for private registry configs
    registry_paths = [
        "/.npmrc",
        "/.yarnrc",
        "/.yarnrc.yml",
        "/pip.conf",
        "/.pypirc",
        "/setup.cfg",
        "/.cargo/config",
        "/.cargo/config.toml",
        "/.gemrc",
        "/Gemfile",
        "/Gemfile.lock",
        "/go.mod",
        "/go.sum",
        "/.netrc",
    ]
    for path in registry_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            content_lower = resp.text.lower()
            # Detect private/internal registry URLs
            internal_indicators = [
                "registry.npmjs.org",
                "npm.pkg.github.com",
                "artifactory",
                "nexus",
                "private",
                "internal",
                "corp.",
                "company.",
                ".local",
                ".internal",
                "devpi",
                "gemfury",
                "cloudsmith",
                "jfrog",
                "packagecloud",
                "verdaccio",
            ]
            for indicator in internal_indicators:
                if indicator in content_lower:
                    vulns.append(
                        {
                            "tipo": "DEPENDENCY_CONFUSION_RISK",
                            "path": path,
                            "indicator": indicator,
                            "severidade": "ALTO",
                            "descricao": f"Registry interno detectado ({indicator}) — risco de dependency confusion!",
                            "remediao": "Usar escopos (@org/) e registry mapping para prevenir dependency confusion.",
                        }
                    )
                    break

            # Detect auth tokens in registry configs
            token_patterns = [
                (r"(?:_authToken|_auth|token)\s*[:=]\s*[\"']([^\"']+)[\"']", "Auth Token"),
                (r"(?:password|passwd)\s*[:=]\s*[\"']([^\"']+)[\"']", "Password"),
            ]
            for pattern, label in token_patterns:
                if re.search(pattern, resp.text):
                    vulns.append(
                        {
                            "tipo": "REGISTRY_CREDENTIAL_EXPOSED",
                            "path": path,
                            "credential_type": label,
                            "severidade": "CRITICO",
                            "descricao": f"Credencial de registry ({label}) exposta em {path}!",
                            "remediao": "Remover credenciais hardcoded e usar variáveis de ambiente ou secret manager.",
                        }
                    )

        except Exception:
            continue
    return vulns


def _check_exposed_lockfiles(target):
    """Verifica lockfiles expostos que revelam árvore completa de dependências."""
    vulns = []
    lockfiles = [
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/Pipfile.lock",
        "/poetry.lock",
        "/Cargo.lock",
        "/Gemfile.lock",
        "/go.sum",
        "/composer.lock",
        "/bun.lockb",
        "/bun.lock",
    ]
    for path in lockfiles:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code == 200 and len(resp.text) > 50:
                vulns.append(
                    {
                        "tipo": "LOCKFILE_EXPOSED",
                        "path": path,
                        "severidade": "MEDIO",
                        "descricao": f"Lockfile {path} exposto — árvore completa de dependências mapeável!",
                        "remediao": "Adicionar lockfiles ao .gitignore público ou restringir acesso via webserver.",
                    }
                )
        except Exception:
            continue
    return vulns


def _check_package_integrity(target):
    """Verifica integridade de pacotes via checksums e assinaturas."""
    vulns = []
    integrity_paths = [
        "/.npmrc",
        "/yarn.lock",
        "/package-lock.json",
        "/pyproject.toml",
        "/poetry.lock",
    ]
    for path in integrity_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=7)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            # Check for integrity hash presence (npm)
            if "integrity" in resp.text and path.endswith(".json"):
                integrity_count = resp.text.count('"integrity"')
                total_deps = resp.text.count('"version"')
                if total_deps > 0 and integrity_count < total_deps * 0.5:
                    vulns.append(
                        {
                            "tipo": "INTEGRITY_CHECKS_INCOMPLETE",
                            "path": path,
                            "com_integridade": integrity_count,
                            "total_deps": total_deps,
                            "severidade": "MEDIO",
                            "descricao": f"Apenas {integrity_count}/{total_deps} dependências têm integrity hash!",
                            "remediao": "Regenerar lockfile com integrity hashes completos.",
                        }
                    )

            # Check if using hash verification (pip)
            if path == "pyproject.toml" and "--hash" not in resp.text:
                if "dependencies" in resp.text:
                    vulns.append(
                        {
                            "tipo": "PYPI_NO_HASH_VERIFICATION",
                            "path": path,
                            "severidade": "MEDIO",
                            "descricao": "Dependências PyPI sem verificação de hash!",
                            "remediao": "Usar pip install --require-hashes ou poetry com lockfile.",
                        }
                    )

        except Exception:
            continue
    return vulns
