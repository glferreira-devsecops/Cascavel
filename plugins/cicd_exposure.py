# plugins/cicd_exposure.py — Cascavel 2026 Intelligence
import requests
import re


CICD_FILES = {
    # GitHub Actions
    "/.github/workflows": ("GITHUB_ACTIONS_DIR", "Diretório de workflows GH Actions"),
    "/.github/workflows/ci.yml": ("GITHUB_CI_YML", "Workflow CI exposto"),
    "/.github/workflows/cd.yml": ("GITHUB_CD_YML", "Workflow CD exposto"),
    "/.github/workflows/deploy.yml": ("GITHUB_DEPLOY_YML", "Workflow deploy exposto"),
    "/.github/CODEOWNERS": ("GITHUB_CODEOWNERS", "CODEOWNERS exposto — team mapping"),
    # GitLab
    "/.gitlab-ci.yml": ("GITLAB_CI", "Pipeline GitLab CI exposto"),
    # Jenkins
    "/Jenkinsfile": ("JENKINSFILE", "Jenkinsfile exposto — secrets leak risk"),
    # CircleCI
    "/.circleci/config.yml": ("CIRCLECI", "Config CircleCI exposta"),
    # Travis
    "/.travis.yml": ("TRAVIS_CI", "Config Travis CI exposta"),
    # Bitbucket
    "/bitbucket-pipelines.yml": ("BITBUCKET", "Config Bitbucket Pipelines"),
    # Azure DevOps
    "/azure-pipelines.yml": ("AZURE_DEVOPS", "Config Azure DevOps exposta"),
    # Drone
    "/.drone.yml": ("DRONE_CI", "Config Drone CI exposta"),
    # GitHub Actions specific
    "/.github/dependabot.yml": ("DEPENDABOT", "Config Dependabot exposta"),
    # Docker
    "/Dockerfile": ("DOCKERFILE", "Dockerfile exposto — build secrets"),
    "/docker-compose.yml": ("DOCKER_COMPOSE", "Docker Compose — infra mapping"),
    "/docker-compose.prod.yml": ("DOCKER_COMPOSE_PROD", "Docker Compose prod"),
    # IaC
    "/.terraform": ("TERRAFORM_DIR", "Diretório Terraform exposto"),
    "/terraform.tfstate": ("TERRAFORM_STATE", "Terraform state — INFRA SECRETS!"),
    "/terraform.tfvars": ("TERRAFORM_VARS", "Terraform variables — credentials!"),
    "/main.tf": ("TERRAFORM_MAIN", "Terraform main config"),
    "/ansible.cfg": ("ANSIBLE_CFG", "Config Ansible exposta"),
    "/playbook.yml": ("ANSIBLE_PLAYBOOK", "Ansible playbook exposto"),
    "/inventory": ("ANSIBLE_INVENTORY", "Ansible inventory — host mapping!"),
    "/Vagrantfile": ("VAGRANT", "Vagrantfile — infra as code"),
    # Environment files
    "/.env": ("ENV_FILE", "Arquivo .env exposto — CREDENTIALS!"),
    "/.env.production": ("ENV_PROD", "Arquivo .env.production exposto!"),
    "/.env.local": ("ENV_LOCAL", "Arquivo .env.local exposto"),
    "/.env.example": ("ENV_EXAMPLE", "Arquivo .env.example"),
    # Build
    "/Makefile": ("MAKEFILE", "Makefile — build commands"),
    "/Rakefile": ("RAKEFILE", "Rakefile exposto"),
    "/Gruntfile.js": ("GRUNTFILE", "Gruntfile exposto"),
    "/webpack.config.js": ("WEBPACK", "Webpack config — build pipeline"),
    "/tsconfig.json": ("TSCONFIG", "TypeScript config"),
    "/package.json": ("PACKAGE_JSON", "package.json — dependencies"),
    # Kubernetes
    "/k8s/": ("K8S_DIR", "Diretório K8s manifests"),
    "/deploy/": ("DEPLOY_DIR", "Diretório deploy"),
    "/helm/": ("HELM_DIR", "Helm charts expostos"),
}

SECRET_PATTERNS = ["password", "secret", "token", "api_key", "aws_",
                    "private_key", "credentials", "apikey", "auth_token",
                    "database_url", "redis_url", "smtp_pass"]


def _check_cicd_files(target):
    """Verifica exposição de arquivos CI/CD e IaC."""
    vulns = []
    for path, (tipo, desc) in CICD_FILES.items():
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 20:
                sev = "CRITICO" if any(k in tipo for k in
                                        ["STATE", "VARS", "ENV_FILE", "ENV_PROD"]) else "ALTO"
                vuln = {
                    "tipo": f"CICD_{tipo}", "path": path,
                    "severidade": sev, "tamanho": len(resp.text),
                    "descricao": desc,
                }
                # Secret detection
                has_secrets = [s for s in SECRET_PATTERNS if s in resp.text.lower()]
                if has_secrets:
                    vuln["secrets_detected"] = has_secrets[:5]
                    vuln["severidade"] = "CRITICO"
                    vuln["descricao"] += f" — SECRETS: {', '.join(has_secrets[:3])}!"
                vulns.append(vuln)
        except Exception:
            continue
    return vulns


def _check_jenkins(target):
    """Verifica Jenkins exposto sem auth."""
    vulns = []
    jenkins_paths = [
        ("/jenkins/", "JENKINS_ROOT"),
        ("/ci/", "CI_ROOT"),
        ("/job/", "JENKINS_JOB"),
        ("/script", "JENKINS_SCRIPT_CONSOLE"),
        ("/manage", "JENKINS_MANAGE"),
        ("/api/json", "JENKINS_API"),
        ("/credentials/", "JENKINS_CREDENTIALS"),
        ("/configureSecurity/", "JENKINS_SECURITY_CONFIG"),
        ("/systemInfo", "JENKINS_SYSTEM_INFO"),
        ("/env-vars.html", "JENKINS_ENV_VARS"),
    ]
    for path, tipo in jenkins_paths:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and any(k in resp.text.lower()
                                                for k in ["jenkins", "hudson", "groovy", "build"]):
                sev = "CRITICO" if "script" in path or "credentials" in path else "ALTO"
                vulns.append({
                    "tipo": f"JENKINS_{tipo}", "path": path,
                    "severidade": sev,
                    "descricao": f"Jenkins {path} acessível — {'RCE via Script Console!' if 'script' in path else 'info disclosure!'}",
                })
        except Exception:
            continue
    return vulns


def _check_github_actions_artifacts(target):
    """Verifica artefatos GitHub Actions públicos."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}/.github/workflows/", timeout=5)
        if resp.status_code == 200:
            yml_files = re.findall(r'href="([^"]*\.(?:yml|yaml))"', resp.text)
            if yml_files:
                vulns.append({
                    "tipo": "GITHUB_WORKFLOWS_LISTED", "severidade": "ALTO",
                    "workflows": yml_files[:10],
                    "descricao": f"{len(yml_files)} workflows GH Actions listáveis!",
                })
    except Exception:
        pass
    return vulns


def run(target, ip, open_ports, banners):
    """
    Scanner CI/CD Pipeline Exposure 2026-Grade.

    Técnicas: 36 CI/CD/IaC files (GH Actions/GitLab/Jenkins/CircleCI/Travis/
    Drone/Bitbucket/Azure DevOps/Terraform/Ansible/Docker/K8s/Helm),
    Jenkins unauth (10 paths incl Script Console/credentials/systemInfo),
    secret detection in exposed files (12 patterns),
    .env/.env.production exposure, Terraform state/vars,
    GitHub workflow listing.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    vulns.extend(_check_cicd_files(target))
    vulns.extend(_check_jenkins(target))
    vulns.extend(_check_github_actions_artifacts(target))

    return {
        "plugin": "cicd_exposure", "versao": "2026.1",
        "tecnicas": ["cicd_files", "jenkins_unauth", "secret_detection",
                      "terraform_state", "env_exposure", "workflow_listing"],
        "resultados": vulns if vulns else "Nenhuma exposição CI/CD detectada",
    }
