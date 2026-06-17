<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>CASCAVEL CTEM ENGINE</code>
</h1>

<h3 align="center">Autonomous Adversarial Exposure Validation (AEV) and Red Team Orchestration Platform.</h3>

<p align="center">
  <strong>Cascavel is a zero-friction Continuous Threat Exposure Management (CTEM) engine. It orchestrates complex attack chains, enriches findings with Threat Intel (EPSS/CISA KEV), generates AI-driven remediation, and exports native telemetry (OCSF) in a single command.</strong>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev"><strong>🌐 cascavel.pages.dev</strong></a> ·
  🇺🇸 <strong>English</strong> ·
  <a href="README.pt-BR.md">🇧🇷 Português (Brasil)</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF.svg?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat-square&logo=python&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Plugins-108-blueviolet.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20WSL%20|%20Windows-0D1B2A.svg?style=flat-square" />
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/CTEM-v3.0-C89F5D.svg?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Reports-OCSF%20|%20PDF%20|%20JSON-28A745.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Security-Hardened%202026-critical?style=flat-square" />
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/security.yml?style=flat-square&label=CI%20Security&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/stargazers"><img src="https://img.shields.io/github/stars/glferreira-devsecops/Cascavel?style=flat-square&color=FFD700" /></a>
</p>

---

## 🦅 Executive Summary & Philosophy

Standard vulnerability management causes critical alert fatigue. Security Operations Centers (SOC) analysts waste hours triaging non-exploitable findings from dozens of non-integrated tools that output incompatible proprietary formats. 

**Cascavel v3.0** shifts organizations from reactive vulnerability management to a proactive, risk-based **Continuous Threat Exposure Management (CTEM)** program. By bridging the gap between business strategy and technical execution, Cascavel ensures that security teams only focus on exposures that pose a credible, reachable risk to the business.

---

## ⚙️ The 5-Stage CTEM Lifecycle (How Cascavel Operates)

Cascavel natively automates Gartner’s five-stage CTEM framework into a single executable pipeline:

### 1. Scoping & Discovery
Unlike traditional tools that rely on hardcoded parameters, Cascavel's **Dynamic Spidering Engine** automatically crawls the target infrastructure (APIs, SaaS integrations, Cloud workloads), mapping forms, headers, and query strings dynamically to construct an accurate attack surface.

### 2. Prioritization
Generic CVSS scores are obsolete. Cascavel enriches every discovered exposure with real-world threat intelligence:
*   **FIRST.org EPSS (Exploit Prediction Scoring System):** Calculates the actual probability of exploitation in the wild within 30 days.
*   **CISA KEV (Known Exploited Vulnerabilities):** Cross-references exposures against active APT/Ransomware campaigns.

### 3. Validation (AEV)
The **Adversarial Exposure Validation (AEV)** engine drops False Positives to near-zero. Cascavel establishes *Global Baselines* for network latency and WAF behaviors *before* scanning. Using Multi-Stage Validation (like `Content-Type` boundary checking), it only reports vulnerabilities that are mathematically and contextually exploitable. 

### 4. Mobilization & Remediation
Instead of dumping JSON files, Cascavel generates **AI-driven remediation payloads**. Using the `--ai-fix` flag, it synthesizes contextual Bash scripts, Python mitigations, or Kubernetes manifests to patch the exact exposure discovered.

### 5. Telemetry & Governance
Cascavel exports native **OCSF (Open Cybersecurity Schema Framework) v1.1.0** telemetry, ensuring immediate compatibility with modern SIEMs (Splunk, Elastic, AWS Security Lake) without custom parsers.

---

## 🎬 See it in Action

<p align="center">
  <img src="docs/cascavel_scan.png" width="700" />
</p>

<p align="center">
  <sub><strong>Cinematic AEV Boot Sequence</strong> · Real-time Threat Preloader · Stealth Simulation</sub>
</p>

<p align="center">
  <img src="docs/cascavel_results.png" width="700" />
</p>

<p align="center">
  <sub><strong>Interactive CTEM Dashboard</strong> · EPSS Tracking · CISA KEV Cross-Correlation</sub>
</p>

---

## 🚀 Deterministic Omni-Distribution Installation

Cascavel v3.0 uses an **Omni-Distribution Pipeline**. It is built, signed, and published across multiple ecosystems simultaneously with SLSA Level 3 Provenance and Cosign cryptographic signatures.

The installer is engineered under a strict 2026 Threat Model, guaranteeing total dependency isolation and preventing supply chain RCE. 

**Does not require `git`. Compatible with macOS, Linux, Windows, WSL2, and Docker.**

### 1. Native Executable (Zero Dependencies)
```bash
# Linux/macOS
curl -sL https://github.com/glferreira-devsecops/Cascavel/releases/latest/download/cascavel-linux -o cascavel
chmod +x cascavel && ./cascavel --help
```

### 2. Docker / GHCR
```bash
docker pull ghcr.io/glferreira-devsecops/cascavel:latest
docker run --rm -it ghcr.io/glferreira-devsecops/cascavel -t target.com
```

### 3. NPM (Node Ecosystem)
```bash
npx cascavel-ctem -t target.com
```

### 4. PyPI (Python Ecosystem)
```bash
pip install cascavel-ctem
cascavel -t target.com
```

### Installer Protections (Hardening v2.0)

| Defense Mechanism | Security Outcome |
|:--|:---|
| **Hermetic Environment** | Isolates via virtualenv (`mktemp -d`) preventing OS-level conflicts. |
| **Zero Supply Chain** | Enforces integrity via hardcoded SHA-256 hashes in `requirements.txt`. |
| **TOCTOU Prevention** | Uses anti-symlink locks and strict `umask 077` permissions. |
| **Clean Exit Hooks** | POSIX `trap` handlers ensure secure deletion of `/tmp` artifacts on exit. |
| **$PATH Isolation** | Prevents Binary Hijacking by stripping relative `.` entries from PATH. |

---

## 🛠️ CLI Reference: Red Team Workflows

The terminal API is designed to be highly tactical and straightforward.

```bash
# Full CTEM Scan (Integrates external binaries + plugins)
cascavel -t target.com

# Stealth Mode: SOC/WAF bypass simulation (Ignores noisy binaries)
cascavel -t target.com --plugins-only --stealth-eval

# Autonomous Workflow: CISA KEV + AI Remediation + OCSF Telemetry
cascavel -t target.com -o ocsf --ai-fix

# Executive Workflow: Generate Legal PDF Report (CVSS v4, ISO 27001)
cascavel -t target.com --pdf

# Surgical Plugin Filter: Run only specific plugins
cascavel -t target.com --plugins-only --plugin-filter sqli_scanner xss_scanner

# CI/CD Integration: Silent Headless Mode
cascavel -t target.com -q -o json
```

### CI/CD Orchestration (GitHub Actions)
Add this as a blocking security gate in your `.github/workflows/ctem.yml`:

```yaml
name: "Cascavel AEV Pipeline"
on: [push, pull_request]
jobs:
  validate-exposure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: curl -sL https://github.com/glferreira-devsecops/Cascavel/releases/latest/download/cascavel-linux -o cascavel && chmod +x cascavel
      - name: Execute CTEM (OCSF + AI Fixes)
        run: ./cascavel -t staging.internal -q -o ocsf --ai-fix
      - name: Upload Telemetry
        uses: actions/upload-artifact@v4
        with:
          name: ocsf-logs
          path: exports/*.jsonl
```

---

## 🧩 Plugin Arsenal (108) and Architecture

Our architecture prioritizes the absolute elimination of false positives via AST parsing and deep semantic detection. 

### Core Engine
```text
cascavel.py (3000+ lines)
├── Stealth Engine ─────────── Requests Hooks, X-COST headers, WAF Rate-Limit Bypass
├── Threat Intel Analyzer ──── Dynamic EPSS (FIRST) and CISA KEV Mapping
├── AI Fix Module ──────────── Sandbox Generation of Mitigation Scripts (Bash/Python)
├── OCSF Telemetry ─────────── EventUID 2002 Export (Linux Foundation Standard)
├── ANSI/Regex Sanitizer ───── Anti-Terminal Injection (CSI/OSC), Anti-ReDoS mitigation
└── PDF Engine ─────────────── Auditable ReportLab PDFs (SHA-256 Checksums)
```

### Infiltration Categories

1. **Injection & Code Exec (7):** `xss_scanner`, `sqli_scanner`, `ssti_scanner`, `rce_scanner`, `nosql_scanner`...
2. **Cloud & K8s Infra (8):** `cloud_metadata` (SSRF via 169.254.x), `docker_exposure`, `s3_bucket_enum`...
3. **Authentication (6):** `jwt_analyzer` (Alg Bypass, Null Signature), `oauth_scanner`, `idor_scanner`...
4. **Defense Bypass (7):** `cors_checker`, `csp_bypass`, `waf_evasion`, `cache_poisoning`...
5. **API Logic Attacks (6):** `graphql_probe`, `mass_assignment`, `api_versioning`...
6. **OSINT and Recon (11):** `shodan_recon`, `dns_rebinding`, `subdomain_takeover`...

For the complete matrix of vectors and pre-calculated CVSS severities, consult our [Plugin Documentation](PLUGINS.md).

---

## 🛡️ Defensive & Supply-Chain Hardening (2026 Standard)

An offensive engine must be immune to retaliation. Cascavel shields its host from traps laid by Blue Teams in HoneyPots, while enforcing rigorous CI/CD supply-chain security.

| Retaliation Vector | Core Defensive Mitigation |
|:---|:---|
| **Terminal Injection (ANSI)** | Strict Regex filters remove malicious Escape payloads (CSI/OSC/DCS), preventing terminal clipboard hijacking. |
| **Command Injection (OS)** | Mandates `--` binary delimiters and blocks native variables in `subprocess.run(shell=False)`. |
| **Server-Side Request Forgery** | Internal IP lock (`169.254.x`) prevents malicious instances from rebounding attacks. `redirects=False` strictly enforced. |
| **Path Traversal Sandboxing** | Utlizes `pathlib.resolve().is_relative_to()` ensuring total containment of OCSF logs and Reports. |
| **Arbitrary Deserialization** | Rejects `pickle` functions and globally enforces `yaml.safe_load()`. |

**Cascavel's own CI/CD pipeline is a fortress:**
*   **Unmasked SAST:** 100% of the codebase is audited by Semgrep, Bandit, and TruffleHog without exclusion filters (`--exclude-rule` granular approach).
*   **Zizmor Hardened:** GitHub Actions workflows are mathematically verified against cache-poisoning, unpinned actions, and privilege escalation vectors.
*   **Cryptographic Signatures:** All Omni-Distribution releases are signed via Sigstore/Cosign.

---

## 🤝 Contributing

Rigid rules ensure Framework integrity:
- All code must pass the Mypy Type Hinting pipeline.
- PEP8 (Ruff) compliance is non-negotiable.
- No arbitrary external packages allowed, preventing dependency chain contamination.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Security Policy](SECURITY.md).

*Cascavel is classified as "Dual-Use". The author repudiates its usage against unauthorized assets.*

---

<p align="center">
  <strong>CASCAVEL METHOD</strong><br />
  <sub>
    Engineered and maintained by <strong>DevFerreiraG</strong><br />
    <a href="https://github.com/glferreira-devsecops">GitHub Profile</a>
  </sub>
</p>
