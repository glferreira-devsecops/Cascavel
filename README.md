<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>CASCAVEL CTEM ENGINE</code>
</h1>

<h3 align="center">Autonomous Adversarial Exposure Validation (AEV) and Red Team orchestration platform.</h3>

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
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20WSL-0D1B2A.svg?style=flat-square" />
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/CTEM-v2.0-C89F5D.svg?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Reports-OCSF%20|%20PDF%20|%20JSON-28A745.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Security-Hardened%202026-critical?style=flat-square" />
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/security.yml?style=flat-square&label=CI%20Security&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/stargazers"><img src="https://img.shields.io/github/stars/glferreira-devsecops/Cascavel?style=flat-square&color=FFD700" /></a>
</p>

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

## The Problem vs. The Solution (CTEM Model)

Standard vulnerability management causes critical alert fatigue. SOC analysts waste hours triaging non-exploitable findings from dozens of non-integrated tools that output incompatible JSON formats.

The **Cascavel AEV (Adversarial Exposure Validation)** engine replaces this fragmented workflow with a unified orchestrated pipeline:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  $ python3 cascavel.py -t target.com -o ocsf --ai-fix --stealth-eval   │
│                                                                        │
│  ┌────────────┐  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │ DISCOVERY  │→ │ EXPOSURE  │→ │   ATTACK   │→ │    ENRICHMENT     │  │
│  └────────────┘  └───────────┘  └────────────┘  └───────────────────┘  │
│   Stealth Recon   WAF Bypass     Exploitation    CISA KEV Match        │
│   OSINT/WHOIS     Cloud Enum     Injections      FIRST.org EPSS Score  │
│                                                                        │
│  ┌────────────┐  ┌──────────────────────────────────────────────────┐  │
│  │REMEDIATION │→ │        OCSF TELEMETRY & PDF REPORTING            │  │
│  └────────────┘  └──────────────────────────────────────────────────┘  │
│   Bash Fixes      Linux Foundation OCSF v1.1.0 Standard                │
│   Python Mitig.   CVSS v4.0 · ISO 27001/SOC 2 Legal Mappings           │
└────────────────────────────────────────────────────────────────────────┘
```

| Capability | Cascavel CTEM Engine | Traditional Tools |
|:---|:---|:---|
| **Unified CTEM Pipeline** | 108 plugins + 30 orchestrated binaries | Fragmented scripts (Nmap + Nuclei) |
| **Intelligence Enrichment** | Automatic CISA KEV and EPSS probability | Requires paid third-party platforms |
| **AI Remediation** | Generates localized corrective scripts (Bash) | Zero active remediation support |
| **Telemetry Standard** | OCSF v1.1.0 output for Splunk/Elastic | Incompatible proprietary JSONs |
| **Evasion (Stealth)** | Advanced `requests` hooks + `X-COST` header | Highly noisy standard User-Agents |
| **Runtime Security** | ANSI Sanitizer, SSRF & TOCTOU Prevention | Blindly trusts external binary output |

---

## Deterministic Installation

The installer is engineered under a strict 2026 Threat Model, guaranteeing total dependency isolation and preventing supply chain RCE. **Does not require `git`. Compatible with macOS, Linux, WSL2, and Docker.**

```bash
curl -sL https://github.com/glferreira-devsecops/Cascavel/releases/latest/download/cascavel-release.tar.gz | tar xz && cd Cascavel && bash install.sh
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

## CLI Reference: Red Team Workflows

The terminal API is designed to be highly tactical and straightforward.

```bash
# Full CTEM Scan (Integrates external binaries + plugins)
python3 cascavel.py -t target.com

# Stealth Mode: SOC/WAF bypass simulation (Ignores noisy binaries)
python3 cascavel.py -t target.com --plugins-only --stealth-eval

# Autonomous Workflow: CISA KEV + AI Remediation + OCSF Telemetry
python3 cascavel.py -t target.com -o ocsf --ai-fix

# Executive Workflow: Generate Legal PDF Report (CVSS v4, ISO 27001)
python3 cascavel.py -t target.com --pdf

# CI/CD Integration: Silent Headless Mode
python3 cascavel.py -t target.com -q -o json
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
        run: curl -sL https://github.com/glferreira-devsecops/Cascavel/releases/latest/download/cascavel-release.tar.gz | tar xz && cd Cascavel && bash install.sh
      - name: Execute CTEM (OCSF + AI Fixes)
        run: cascavel -t staging.internal -q -o ocsf --ai-fix
      - name: Upload Telemetry
        uses: actions/upload-artifact@v4
        with:
          name: ocsf-logs
          path: exports/*.jsonl
```

---

## Plugin Arsenal (108) and Architecture

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

## Defensive Hardening Model

An offensive engine must be immune to retaliation. Cascavel shields its host from traps laid by Blue Teams in HoneyPots.

| Retaliation Vector | Core Defensive Mitigation |
|:---|:---|
| **Terminal Injection (ANSI)** | Strict Regex filters remove malicious Escape payloads (CSI/OSC/DCS), preventing terminal clipboard hijacking. |
| **Command Injection (OS)** | Mandates `--` binary delimiters and blocks native variables in `subprocess.run(shell=False)`. |
| **Server-Side Request Forgery** | Internal IP lock (`169.254.x`) prevents malicious instances from rebounding attacks. `redirects=False` strictly enforced. |
| **Path Traversal Sandboxing** | Utlizes `pathlib.resolve().is_relative_to()` ensuring total containment of OCSF logs and Reports. |
| **Arbitrary Deserialization** | Rejects `pickle` functions and globally enforces `yaml.safe_load()`. |

---

## Contributing

Rigid rules ensure Framework integrity:
- All code must pass the Mypy Type Hinting pipeline.
- PEP8 (Flake8) compliance is non-negotiable.
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
