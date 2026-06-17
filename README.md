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
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20WSL-0D1B2A.svg?style=flat-square" />
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

**Does not require `git`. Compatible with macOS, Linux, Windows, and Docker.**

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

---

## 🛠️ Usage & Operational Assets

Run a full Continuous Threat Exposure scan with OCSF telemetry, Stealth Evaluation, and AI-driven remediation:

```bash
cascavel -t target.com -o ocsf --ai-fix --stealth-eval
```

Run specific plugins (e.g., XSS and SQLi only) using the surgical Plugin Filter:

```bash
cascavel -t target.com --plugins-only --plugin-filter sqli_scanner xss_scanner
```

---

## 🛡️ Security & Supply-Chain Hardening (2026 Standard)

Cascavel's own CI/CD pipeline is a fortress.
*   **Unmasked SAST:** 100% of the codebase is audited by Semgrep, Bandit, and TruffleHog without exclusion filters.
*   **Zizmor Hardened:** GitHub Actions workflows are mathematically verified against cache-poisoning, unpinned actions, and privilege escalation vectors.
*   **Cryptographic Signatures:** All releases are signed via Sigstore/Cosign.

<p align="center">
  Made with 🐍 by <a href="https://github.com/glferreira-devsecops">DevFerreiraG</a>
</p>
