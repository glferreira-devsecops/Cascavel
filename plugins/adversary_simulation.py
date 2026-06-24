"""
MITRE ATT&CK Adversary Simulation — Map vulnerabilities to techniques,
generate attack chains, simulate lateral movement and persistence paths.
"""

import logging
import re
from typing import Any

logger = logging.getLogger("Cascavel.Plugins.AdversarySimulation")

# MITRE ATT&CK technique mappings based on common vulnerability patterns
VULN_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "sqli": {
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
        "description": "SQL injection on public-facing service allows initial foothold.",
    },
    "rce": {
        "technique": "T1059",
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter",
        "description": "Remote code execution enables arbitrary command execution on the target.",
    },
    "ssrf": {
        "technique": "T1552",
        "tactic": "Credential Access",
        "name": "Unsecured Credentials",
        "description": "SSRF can leak cloud metadata credentials (IMDS, environment variables).",
    },
    "lfi": {
        "technique": "T1005",
        "tactic": "Collection",
        "name": "Data from Local System",
        "description": "Local file inclusion exposes sensitive files (passwd, shadow, configs).",
    },
    "xss": {
        "technique": "T1189",
        "tactic": "Initial Access",
        "name": "Drive-by Compromise",
        "description": "Stored XSS can be weaponized for session hijacking or drive-by attacks.",
    },
    "idor": {
        "technique": "T1539",
        "tactic": "Credential Access",
        "name": "Steal Web Session Cookie",
        "description": "IDOR allows accessing other users' data and session tokens.",
    },
    "csrf": {
        "technique": "T1204",
        "tactic": "Execution",
        "name": "User Execution",
        "description": "CSRF forces authenticated users to perform unintended actions.",
    },
    "xxe": {
        "technique": "T1203",
        "tactic": "Execution",
        "name": "Exploitation for Client Execution",
        "description": "XXE can lead to SSRF, file disclosure, or RCE via external entities.",
    },
    "ssti": {
        "technique": "T1059",
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter",
        "description": "Server-side template injection achieves RCE via template engine abuse.",
    },
    "deserialization": {
        "technique": "T1059.007",
        "tactic": "Execution",
        "name": "JavaScript/JScript/VBScript",
        "description": "Unsafe deserialization enables remote code execution via crafted objects.",
    },
    "smuggling": {
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
        "description": "HTTP request smuggling bypasses security controls and enables cache poisoning.",
    },
    "misconfiguration": {
        "technique": "T1592",
        "tactic": "Reconnaissance",
        "name": "Gather Victim Host Information",
        "description": "Security misconfigurations expose internal architecture and attack surface.",
    },
    "default_credentials": {
        "technique": "T1078",
        "tactic": "Persistence",
        "name": "Valid Accounts",
        "description": "Default credentials provide persistent access without exploitation.",
    },
    "open_redirect": {
        "technique": "T1566.002",
        "tactic": "Initial Access",
        "name": "Phishing: Spearphishing Link",
        "description": "Open redirects weaponize phishing links against the target domain.",
    },
    "jwt": {
        "technique": "T1550",
        "tactic": "Defense Evasion",
        "name": "Use Alternate Authentication Material",
        "description": "JWT weaknesses (alg confusion, weak secrets) allow token forgery.",
    },
    "graphql": {
        "technique": "T1213",
        "tactic": "Collection",
        "name": "Data from Information Repositories",
        "description": "GraphQL introspection exposes full schema and enables targeted data exfiltration.",
    },
    "cors": {
        "technique": "T1119",
        "tactic": "Collection",
        "name": "Automated Collection",
        "description": "Misconfigured CORS allows cross-origin data theft from authenticated users.",
    },
}

# Persistence techniques to check
PERSISTENCE_CHECKS: list[dict[str, str]] = [
    {
        "technique": "T1136",
        "name": "Create Account",
        "check": "default_credentials",
        "description": "Test if default admin credentials are active (admin:admin, root:root).",
    },
    {
        "technique": "T1505.003",
        "name": "Web Shell",
        "check": "upload_write",
        "description": "Check if file upload allows web shell deployment.",
    },
    {
        "technique": "T1098",
        "name": "Account Manipulation",
        "check": "privilege_escalation",
        "description": "Test if low-privilege users can escalate via mass assignment or IDOR.",
    },
    {
        "technique": "T1546",
        "name": "Event Triggered Execution",
        "check": "ssti_rce",
        "description": "SSTI payloads can establish persistent backdoors via template auto-loading.",
    },
    {
        "technique": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "check": "cloud_metadata",
        "description": "Leaked cloud credentials via SSRF provide persistent cloud access.",
    },
]

# Lateral movement paths based on findings
LATERAL_MOVEMENT_PATHS: list[dict[str, Any]] = [
    {
        "from": "public_web",
        "to": "internal_api",
        "technique": "T1090",
        "name": "Proxy",
        "trigger": "ssrf",
        "description": "SSRF pivots from public web to internal APIs not exposed externally.",
    },
    {
        "from": "web_app",
        "to": "database",
        "technique": "T1213",
        "name": "Data from Information Repositories",
        "trigger": "sqli",
        "description": "SQL injection pivots from web tier to database tier.",
    },
    {
        "from": "web_app",
        "to": "file_system",
        "technique": "T1005",
        "name": "Data from Local System",
        "trigger": "lfi",
        "description": "LFI pivots from application context to host file system.",
    },
    {
        "from": "client",
        "to": "admin_session",
        "technique": "T1539",
        "name": "Steal Web Session Cookie",
        "trigger": "xss",
        "description": "XSS hijacks admin session cookies, pivoting from client to admin context.",
    },
    {
        "from": "web_app",
        "to": "cloud_infra",
        "technique": "T1552.005",
        "name": "Cloud Instance Metadata API",
        "trigger": "ssrf",
        "description": "SSRF to cloud metadata endpoint (169.254.169.254) leaks IAM credentials.",
    },
    {
        "from": "api",
        "to": "internal_services",
        "technique": "T1021",
        "name": "Remote Services",
        "trigger": "rce",
        "description": "RCE on API server enables pivoting to internal microservices via service mesh.",
    },
]

# Defense evasion opportunities
DEFENSE_EVASION: list[dict[str, str]] = [
    {
        "technique": "T1027",
        "name": "Obfuscated Files or Information",
        "trigger": "waf_present",
        "description": "WAF detected — test payload obfuscation bypasses (encoding, fragmentation, case variation).",
    },
    {
        "technique": "T1070.004",
        "name": "Indicator Removal: File Deletion",
        "trigger": "log_misconfig",
        "description": "Check if application logs can be cleared via LFI or log injection.",
    },
    {
        "technique": "T1036",
        "name": "Masquerading",
        "trigger": "open_redirect",
        "description": "Open redirects enable phishing with legitimate domain, evading email filters.",
    },
    {
        "technique": "T1550.004",
        "name": "Web Session Cookie",
        "trigger": "jwt_weakness",
        "description": "Weak JWT secrets allow forging session tokens without authentication.",
    },
    {
        "technique": "T1090.001",
        "name": "Internal Proxy",
        "trigger": "ssrf",
        "description": "SSRF chains into internal proxy for anonymized attack traffic.",
    },
]


def _classify_findings(banners: dict[str, str], context: dict | None) -> list[str]:
    """Extract vulnerability categories from banners and context."""
    categories: set[str] = set()
    all_text = " ".join(str(v) for v in banners.values()).lower()

    if context:
        for finding in context.get("findings", []):
            if isinstance(finding, dict):
                all_text += " " + str(finding.get("vulnerability", "")).lower()
                all_text += " " + str(finding.get("description", "")).lower()

    pattern_map = {
        "sqli": r"sql.?inject|sqli|mysql|postgresql|mssql|oracle",
        "rce": r"remote.?code|rce|command.?inject|code.?exec",
        "ssrf": r"ssrf|server.?side.?request|internal.?request|169\.254",
        "lfi": r"local.?file|lfi|path.?traversal|directory.?traversal|\.\.\/",
        "xss": r"cross.?site.?script|xss|reflected|stored.?xss|dom.?xss",
        "idor": r"insecure.?direct|idor|object.?reference",
        "csrf": r"cross.?site.?request.?forgery|csrf|xsrf",
        "xxe": r"xml.?external|xxe|external.?entity",
        "ssti": r"template.?inject|ssti|server.?side.?template",
        "deserialization": r"deserializ|insecure.?deserializ|object.?injection",
        "smuggling": r"smuggl|http.?request.?smuggl|cl.?te|te.?cl",
        "misconfiguration": r"misconfig|default.?config|information.?disclos",
        "default_credentials": r"default.?credential|default.?pass|admin:?admin",
        "open_redirect": r"open.?redirect|url.?redirect|unvalidated.?redirect",
        "jwt": r"jwt|json.?web.?token|token.?forg|alg.?confusion",
        "graphql": r"graphql|introspect|query.?language",
        "cors": r"cors|cross.?origin.?resource.?sharing|access.?control.?allow",
    }

    for category, pattern in pattern_map.items():
        if re.search(pattern, all_text):
            categories.add(category)

    return sorted(categories)


def _build_attack_chains(categories: list[str]) -> list[dict[str, Any]]:
    """Generate multi-step attack chains from discovered vulnerability categories."""
    chains: list[dict[str, Any]] = []

    # Chain 1: SSRF -> Cloud Credential Theft -> Lateral Movement
    if "ssrf" in categories:
        chains.append({
            "chain_id": "CHAIN-SSRF-CLOUD",
            "severity": "CRITICO",
            "steps": [
                {"step": 1, "technique": "T1552.005", "action": "Probe internal services via SSRF (169.254.169.254, 127.0.0.1)"},
                {"step": 2, "technique": "T1552", "action": "Extract cloud IAM credentials from metadata endpoint"},
                {"step": 3, "technique": "T1098", "action": "Use stolen credentials to create backdoor IAM user"},
                {"step": 4, "technique": "T1078", "action": "Persistent access via valid cloud account"},
            ],
            "mitigation": "Enforce IMDSv2, block metadata IP at network level, rotate IAM credentials regularly.",
        })

    # Chain 2: SQLi -> Database Dump -> Credential Reuse
    if "sqli" in categories:
        chains.append({
            "chain_id": "CHAIN-SQLI-DATA",
            "severity": "CRITICO",
            "steps": [
                {"step": 1, "technique": "T1190", "action": "Exploit SQL injection on input parameter"},
                {"step": 2, "technique": "T1213", "action": "Dump user credentials database (passwords, tokens)"},
                {"step": 3, "technique": "T1078", "action": "Test leaked credentials on other services (credential stuffing)"},
                {"step": 4, "technique": "T1021", "action": "Pivot to internal services with reused credentials"},
            ],
            "mitigation": "Parameterized queries, credential hashing (bcrypt/argon2), network segmentation.",
        })

    # Chain 3: XSS -> Session Hijack -> Admin Access
    if "xss" in categories:
        chains.append({
            "chain_id": "CHAIN-XSS-HIJACK",
            "severity": "ALTO",
            "steps": [
                {"step": 1, "technique": "T1189", "action": "Inject stored XSS payload in user-controlled field"},
                {"step": 2, "technique": "T1539", "action": "Steal admin session cookie via document.cookie exfiltration"},
                {"step": 3, "technique": "T1078", "action": "Replay admin session to access privileged functions"},
                {"step": 4, "technique": "T1505.003", "action": "Deploy web shell via admin file upload"},
            ],
            "mitigation": "HttpOnly + Secure + SameSite cookies, CSP headers, output encoding.",
        })

    # Chain 4: LFI -> Config Leak -> Credential Extraction
    if "lfi" in categories:
        chains.append({
            "chain_id": "CHAIN-LFI-CONFIG",
            "severity": "ALTO",
            "steps": [
                {"step": 1, "technique": "T1005", "action": "Read /etc/passwd and application config files via LFI"},
                {"step": 2, "technique": "T1552", "action": "Extract database credentials, API keys from config"},
                {"step": 3, "technique": "T1213", "action": "Connect directly to database with extracted credentials"},
                {"step": 4, "technique": "T1098", "action": "Create admin account in database"},
            ],
            "mitigation": "Input validation, chroot environments, principle of least privilege for file access.",
        })

    # Chain 5: SSTI -> RCE -> Persistence
    if "ssti" in categories:
        chains.append({
            "chain_id": "CHAIN-SSTI-RCE",
            "severity": "CRITICO",
            "steps": [
                {"step": 1, "technique": "T1203", "action": "Inject SSTI payload ({{config.__class__.__mro__[1].__subclasses__()}})"},
                {"step": 2, "technique": "T1059", "action": "Achieve RCE via template engine OS command execution"},
                {"step": 3, "technique": "T1505.003", "action": "Deploy persistent web shell"},
                {"step": 4, "technique": "T1053", "action": "Install cron job for scheduled reverse shell"},
            ],
            "mitigation": "Sandboxed template rendering, input sanitization, WAF rules for template injection patterns.",
        })

    # Chain 6: Smuggling -> Cache Poisoning -> Mass Exploitation
    if "smuggling" in categories:
        chains.append({
            "chain_id": "CHAIN-SMUGGLE-CACHE",
            "severity": "ALTO",
            "steps": [
                {"step": 1, "technique": "T1190", "action": "Craft CL-TE or TE-CL desync payload"},
                {"step": 2, "technique": "T1185", "action": "Poison cache with malicious response"},
                {"step": 3, "technique": "T1189", "action": "Deliver poisoned content to legitimate users"},
                {"step": 4, "technique": "T1539", "action": "Harvest session tokens from poisoned responses"},
            ],
            "mitigation": "Normalize request parsing, disable HTTP/1.1 pipelineing, use HTTP/2 end-to-end.",
        })

    # Chain 7: JWT Forgery -> Privilege Escalation
    if "jwt" in categories:
        chains.append({
            "chain_id": "CHAIN-JWT-ESCALATE",
            "severity": "CRITICO",
            "steps": [
                {"step": 1, "technique": "T1550.004", "action": "Identify JWT signing algorithm (HS256/RS256 confusion)"},
                {"step": 2, "technique": "T1550.004", "action": "Forge token with alg:none or brute-force weak secret"},
                {"step": 3, "technique": "T1078", "action": "Modify claims (role=admin, sub=target_user)"},
                {"step": 4, "technique": "T1098", "action": "Access admin endpoints with forged token"},
            ],
            "mitigation": "Enforce RS256/ES256, strong secrets (256-bit+), token expiry, audience validation.",
        })

    return chains


def _check_persistence(categories: list[str]) -> list[dict[str, Any]]:
    """Identify persistence mechanisms available based on findings."""
    findings: list[dict[str, Any]] = []
    for check in PERSISTENCE_CHECKS:
        trigger = check["check"]
        if trigger == "default_credentials" and "default_credentials" in categories:
            findings.append({
                "technique": check["technique"],
                "name": check["name"],
                "severity": "CRITICO",
                "description": check["description"],
                "remediation": "Change all default credentials, enforce strong password policy, disable unused accounts.",
            })
        elif trigger == "upload_write" and ("rce" in categories or "ssti" in categories):
            findings.append({
                "technique": check["technique"],
                "name": check["name"],
                "severity": "ALTO",
                "description": check["description"],
                "remediation": "Restrict file upload types, store outside webroot, scan uploaded files.",
            })
        elif trigger == "privilege_escalation" and ("idor" in categories or "mass_assignment" in str(categories)):
            findings.append({
                "technique": check["technique"],
                "name": check["name"],
                "severity": "ALTO",
                "description": check["description"],
                "remediation": "Server-side authorization checks, deny-by-default for sensitive fields.",
            })
        elif trigger == "ssti_rce" and "ssti" in categories:
            findings.append({
                "technique": check["technique"],
                "name": check["name"],
                "severity": "CRITICO",
                "description": check["description"],
                "remediation": "Use logic-less templates, sandbox template execution, block OS-level calls.",
            })
        elif trigger == "cloud_metadata" and "ssrf" in categories:
            findings.append({
                "technique": check["technique"],
                "name": check["name"],
                "severity": "CRITICO",
                "description": check["description"],
                "remediation": "Enforce IMDSv2, use VPC endpoint policies, rotate credentials.",
            })

    return findings


def _check_lateral_movement(categories: list[str]) -> list[dict[str, Any]]:
    """Identify lateral movement paths based on discovered vulnerabilities."""
    findings: list[dict[str, Any]] = []
    for path in LATERAL_MOVEMENT_PATHS:
        if path["trigger"] in categories:
            findings.append({
                "technique": path["technique"],
                "name": path["name"],
                "source": path["from"],
                "target": path["to"],
                "severity": "ALTO",
                "description": path["description"],
                "remediation": "Network segmentation, zero-trust microsegmentation, internal service authentication.",
            })
    return findings


def _check_defense_evasion(categories: list[str]) -> list[dict[str, Any]]:
    """Identify defense evasion opportunities for the adversary."""
    findings: list[dict[str, Any]] = []
    for evasion in DEFENSE_EVASION:
        trigger = evasion["trigger"]
        if trigger == "waf_present" and ("xss" in categories or "sqli" in categories):
            findings.append({
                "technique": evasion["technique"],
                "name": evasion["name"],
                "severity": "MEDIO",
                "description": evasion["description"],
                "remediation": "Layer WAF with RASP, behavioral analysis, and request normalization.",
            })
        elif trigger == "log_misconfig" and "lfi" in categories:
            findings.append({
                "technique": evasion["technique"],
                "name": evasion["name"],
                "severity": "MEDIO",
                "description": evasion["description"],
                "remediation": "Centralized immutable logging (SIEM), restrict log file access.",
            })
        elif trigger == "open_redirect" and "open_redirect" in categories:
            findings.append({
                "technique": evasion["technique"],
                "name": evasion["name"],
                "severity": "BAIXO",
                "description": evasion["description"],
                "remediation": "Whitelist redirect destinations, use relative paths only.",
            })
        elif trigger == "jwt_weakness" and "jwt" in categories:
            findings.append({
                "technique": evasion["technique"],
                "name": evasion["name"],
                "severity": "ALTO",
                "description": evasion["description"],
                "remediation": "Strong signing algorithms (ES256), short token expiry, token revocation list.",
            })
        elif trigger == "ssrf" and "ssrf" in categories:
            findings.append({
                "technique": evasion["technique"],
                "name": evasion["name"],
                "severity": "MEDIO",
                "description": evasion["description"],
                "remediation": "Egress filtering, SSRF-aware URL validation, disable unnecessary protocols.",
            })

    return findings


def run(
    target: str,
    ip: str,
    ports: list[int],
    banners: dict[str, str],
    context: dict | None = None,
) -> dict[str, Any] | None:
    """Main plugin entry point — MITRE ATT&CK adversary simulation."""
    resultados: list[dict[str, Any]] = []

    try:
        categories = _classify_findings(banners, context)

        if not categories:
            resultados.append({
                "tipo": "INFO",
                "severidade": "INFO",
                "titulo": "No vulnerabilities to simulate",
                "descricao": "No known vulnerability categories detected for adversary simulation. "
                             "Run vulnerability scanners first for richer simulation output.",
                "tecnica": "N/A",
                "remediacao": "N/A",
            })
            return {"plugin": "adversary_simulation", "resultados": resultados}

        # 1. Vulnerability-to-Technique Mapping
        for cat in categories:
            if cat in VULN_TECHNIQUE_MAP:
                tech = VULN_TECHNIQUE_MAP[cat]
                resultados.append({
                    "tipo": "ATTACK_MAPPING",
                    "severidade": "INFO",
                    "titulo": f"ATT&CK Mapping: {cat.upper()} -> {tech['technique']}",
                    "descricao": f"{tech['name']} ({tech['tactic']}): {tech['description']}",
                    "tecnica": tech["technique"],
                    "tatica": tech["tactic"],
                    "remediacao": "Refer to MITRE ATT&CK mitigation guidance for the mapped technique.",
                })

        # 2. Attack Chains
        chains = _build_attack_chains(categories)
        for chain in chains:
            resultados.append({
                "tipo": "ATTACK_CHAIN",
                "severidade": chain["severity"],
                "titulo": f"Attack Chain: {chain['chain_id']}",
                "descricao": f"Multi-step attack chain with {len(chain['steps'])} stages identified.",
                "steps": chain["steps"],
                "remediacao": chain["mitigation"],
            })

        # 3. Persistence Mechanisms
        persistence = _check_persistence(categories)
        for p in persistence:
            resultados.append({
                "tipo": "PERSISTENCE",
                "severidade": p["severity"],
                "titulo": f"Persistence: {p['name']} ({p['technique']})",
                "descricao": p["description"],
                "tecnica": p["technique"],
                "remediacao": p["remediation"],
            })

        # 4. Lateral Movement Paths
        lateral = _check_lateral_movement(categories)
        for lm in lateral:
            resultados.append({
                "tipo": "LATERAL_MOVEMENT",
                "severidade": lm["severity"],
                "titulo": f"Lateral Movement: {lm['source']} -> {lm['target']} ({lm['technique']})",
                "descricao": lm["description"],
                "tecnica": lm["technique"],
                "origem": lm["source"],
                "destino": lm["target"],
                "remediacao": lm["remediation"],
            })

        # 5. Defense Evasion
        evasion = _check_defense_evasion(categories)
        for ev in evasion:
            resultados.append({
                "tipo": "DEFENSE_EVASION",
                "severidade": ev["severity"],
                "titulo": f"Defense Evasion: {ev['name']} ({ev['technique']})",
                "descricao": ev["description"],
                "tecnica": ev["technique"],
                "remediacao": ev["remediation"],
            })

        # Summary
        severities = [r["severidade"] for r in resultados]
        crit_count = severities.count("CRITICO")
        alto_count = severities.count("ALTO")

        resultados.insert(0, {
            "tipo": "RESUMO",
            "severidade": "CRITICO" if crit_count > 0 else ("ALTO" if alto_count > 0 else "MEDIO"),
            "titulo": f"Adversary Simulation Summary — {len(categories)} categories, {len(chains)} attack chains",
            "descricao": (
                f"Identified {len(categories)} vulnerability categories mapped to MITRE ATT&CK. "
                f"Generated {len(chains)} multi-stage attack chains, "
                f"{len(persistence)} persistence mechanisms, "
                f"{len(lateral)} lateral movement paths, "
                f"{len(evasion)} defense evasion opportunities."
            ),
            "categorias_detectadas": categories,
            "total_resultados": len(resultados),
            "remediacao": "Prioritize CRITICAL attack chains. Implement defense-in-depth: WAF + RASP + network segmentation + immutable logging.",
        })

        return {"plugin": "adversary_simulation", "resultados": resultados}

    except Exception as e:
        logger.error(f"Adversary simulation failed for {target}: {e}")
        return {
            "plugin": "adversary_simulation",
            "resultados": [{
                "tipo": "ERRO",
                "severidade": "INFO",
                "titulo": "Simulation error",
                "descricao": f"Adversary simulation failed: {e}",
                "remediacao": "N/A",
            }],
        }
