<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>🐍 CASCAVEL</code>
</h1>

<h3 align="center">Offensive Security Framework — Red Team Intelligence Engine</h3>

<p align="center">
  <strong>84 security plugins · 30+ recon tools · OWASP 2025 · CVSS v4.0 · PDF/MD/JSON reports</strong><br />
  One command to enumerate, scan, exploit, analyze, and generate compliance-ready pentest reports.<br />
  Built for red teamers, bug bounty hunters, and DevSecOps engineers.
</p>

<p align="center">
  🇺🇸 <strong>English</strong> ·
  <a href="README.pt-BR.md">🇧🇷 Português (Brasil)</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF.svg?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat-square&logo=python&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Plugins-84-blueviolet.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20WSL-0D1B2A.svg?style=flat-square" />
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/v2.2.0-C89F5D.svg?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Reports-PDF%20|%20MD%20|%20JSON-28A745.svg?style=flat-square" />
  <img src="https://img.shields.io/badge/Security-Hardened%202026-critical?style=flat-square" />
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Open%20Source-00D4FF.svg?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01ek0yIDE3bDEwIDUgMTAtNS0xMC01LTEwIDV6TTIgMTJsMTAgNSAxMC01LTEwLTUtMTAgNXoiLz48L3N2Zz4=" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/security.yml?style=flat-square&label=CI%20Security&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/issues"><img src="https://img.shields.io/github/issues/glferreira-devsecops/Cascavel?style=flat-square&color=yellow" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/ci.yml?style=flat-square&label=CI&logo=github" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/glferreira-devsecops/Cascavel"><img src="https://img.shields.io/ossf-scorecard/github.com/glferreira-devsecops/Cascavel?style=flat-square&label=OpenSSF%20Scorecard" /></a>
  <a href="https://www.bestpractices.dev/projects/12255"><img src="https://www.bestpractices.dev/projects/12255/badge" alt="OpenSSF Best Practices" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/actions/workflows/codeql.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/Cascavel/codeql.yml?style=flat-square&label=CodeQL&logo=github" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/stargazers"><img src="https://img.shields.io/github/stars/glferreira-devsecops/Cascavel?style=flat-square&color=FFD700" /></a>
  <a href="https://github.com/glferreira-devsecops/Cascavel/network/members"><img src="https://img.shields.io/github/forks/glferreira-devsecops/Cascavel?style=flat-square&color=00D4FF" /></a>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev">Website</a> · 
  <a href="#-install">Install</a> · 
  <a href="#-what-makes-cascavel-different">Why Cascavel</a> · 
  <a href="#-architecture">Architecture</a> · 
  <a href="#-plugin-arsenal-84">Plugins</a> · 
  <a href="#-cli-reference">CLI</a> · 
  <a href="#-pdf-reports-v220">Reports</a> · 
  <a href="#-security-hardening">Security</a> · 
  <a href="#-contributing">Contributing</a>
</p>

---

## 🎬 Demo

<p align="center">
  <img src="docs/cascavel_scan.png" width="700" />
</p>

<p align="center">
  <sub><strong>Cinematic boot sequence</strong> · Auto-detects 30+ tools · Preloader with security intel tips</sub>
</p>

<p align="center">
  <img src="docs/cascavel_results.png" width="700" />
</p>

<p align="center">
  <sub><strong>Split-screen live dashboard</strong> · Real-time severity tracking · Rotating security intelligence</sub>
</p>

---

## 💡 What Makes Cascavel Different

Most pentest workflows involve **20+ separate tools**, each with its own syntax, output format, and report style. You manually merge results, format reports, and lose hours to context-switching.

**Cascavel replaces the entire workflow:**

```
┌─────────────────────────────────────────────────────────┐
│  $ python3 cascavel.py -t target.com --pdf              │
│                                                         │
│  ┌──────────┐  ┌────────┐  ┌──────────┐  ┌──────────┐  │
│  │ DISCOVER │→ │ PROBE  │→ │  ATTACK  │→ │ ANALYZE  │  │
│  └──────────┘  └────────┘  └──────────┘  └──────────┘  │
│   Subdomains    Ports       XSS,SQLi      JWT,CORS     │
│   DNS,WHOIS     Banners     SSRF,RCE      CSP,CSRF     │
│   Cloud enum    Headers     SSTI,XXE      OAuth,IDOR    │
│                                                         │
│  ┌──────────┐  ┌──────────────────────────────────────┐ │
│  │  DETECT  │→ │         REPORT (PDF/MD/JSON)         │ │
│  └──────────┘  └──────────────────────────────────────┘ │
│   Docker,K8s    CVSS v4.0 · OWASP · PTES · LGPD        │
│   Redis,S3      Legal disclaimers · SHA-256 integrity   │
│   CI/CD         Compliance mapping · Risk matrix        │
└─────────────────────────────────────────────────────────┘
```

| Capability | Cascavel | Other Tools |
|:---|:---|:---|
| **Unified pipeline** | 84 plugins + 30 tools in one command | Fragmented scripts |
| **Live dashboard** | Split-screen with real-time stats + intel | No live feedback |
| **PDF reports** | 12 legal disclaimers, CVSS v4.0, PTES | Manual formatting |
| **Terminal UX** | Cinematic preloader, fade animations | Plain stdout |
| **Security hardening** | ANSI sanitizer, plugin sandboxing | Trust all output |
| **Zero-config** | `install.sh` handles everything | Manual dependency hell |

---

## ⚡ Install

### Prerequisites

| Requirement | Minimum | Why |
|:---|:---|:---|
| **Python** | 3.12+ | LTS until 2028 · `importlib.metadata`, typed generics |
| **requests** | 2.32.4 | GHSA-9hjg — `.netrc` credential leak + TLS verify bypass |
| **pyOpenSSL** | 25.0.0 | GHSA-5pwr — buffer overflow + unhandled callback bypass |
| **dnspython** | 2.7.0 | GHSA-3rq5 — TuDoor DNS resolution disruption |
| **PyJWT** | 2.12.0 | CVE-2022-29217 — algorithm confusion attack |
| **ReportLab** | 3.6.13 | CVE-2023-33733 — RCE via `rl_safe_eval` |

> [!NOTE]
> The installer automatically enforces these minimum versions and runs `pip-audit` post-install. Manual installs should verify with `pip list | grep -iE 'requests|pyopenssl|dnspython|pyjwt|reportlab'`.

### 🚀 Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/Cascavel/main/install.sh | bash
```

**One command. That's it.** Works on macOS, Linux (Debian/Ubuntu/Kali/Parrot/Fedora/Arch/Alpine/SUSE), WSL2, and Docker. The installer auto-detects your OS, installs `git` + `python3` if missing, clones the repo, creates a venv, installs all 84 plugins + 30 tools, and registers the `cascavel` global command. **Zero manual steps.**

> [!TIP]
> No `curl`? Use `wget -qO- https://raw.githubusercontent.com/glferreira-devsecops/Cascavel/main/install.sh | bash`

<details>
<summary><strong>📋 Alternative methods (git clone, Docker, manual)</strong></summary>

```bash
# Git clone
git clone https://github.com/glferreira-devsecops/Cascavel.git && cd Cascavel && bash install.sh

# Download tarball (no git needed)
curl -fsSL https://github.com/glferreira-devsecops/Cascavel/archive/main.tar.gz | tar xz && cd Cascavel-main && bash install.sh

# Docker (isolated)
docker run -it --rm python:3.12-slim bash -c "apt update && apt install -y git && git clone https://github.com/glferreira-devsecops/Cascavel.git /app && cd /app && bash install.sh"

# Manual
git clone https://github.com/glferreira-devsecops/Cascavel.git && cd Cascavel
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && python3 cascavel.py -t target.com
```

</details>

The installer v2.3.0 includes **15 security hardenings**: `trap` cleanup, `mktemp -d` TOCTOU isolation, anti-symlink lock, SHA-256 `requirements.txt` integrity, CVE version enforcement (6 packages), `umask 077`, PATH prefix sanitization (rejects `.` and relative paths), container detection (Docker/Podman/LXC), WSL2 kernel detection, Python `ssl` module verification, stale venv recovery, `chmod 700/600` on sensitive paths, GOPATH/GOBIN export validation, locale UTF-8 enforcement, and absolute paths for critical binaries.

---

## 🏗️ Architecture

```
cascavel.py (2800+ lines)                    report_generator.py (1400+ lines)
├── ANSI Escape Sanitizer                     ├── _NumberedCanvas (two-pass "Page X of Y")
│   └── Blocks CSI/OSC/DCS injection          ├── Diagonal "CONFIDENCIAL" watermark
├── Preloader Engine                          ├── QR Code → rettecnologia.org
│   └── 5-stage cinematic boot                ├── Widows/orphans paragraph control
├── Plugin Orchestrator                       ├── Table splitOn + repeatRows=1
│   └── Dynamic load, SIGALRM timeout         ├── Risk Matrix (5×5 heat map)
├── Split-Screen Dashboard                    ├── 9 compliance frameworks
│   └── Rich Live (scan + intel panel)        ├── 20-term security glossary
├── External Tools Pipeline                   ├── Prioritized remediation summary
│   └── 30+ tools, shlex.quote()              └── SHA-256 document integrity
├── Report Engine (PDF/MD/JSON)
└── Signal Handler (async-signal-safe)
```

### Terminal UX Engine (21 Hardenings)

| # | Protection | Implementation |
|:--|:---|:---|
| 1 | Terminal height detection | `_get_terminal_height()` — POSIX fallback for headless/pipe |
| 2 | Logo fade term detection | Skips cursor manipulation on terminals < 20 rows |
| 3 | Cursor safety clamp | `_clear_block` — never moves cursor beyond boundaries |
| 4 | Preloader fallback | `try/except` wrapper for CI/pipe/dumb terminals |
| 5 | Typewriter interrupt | Guarantees newline before SIGINT propagation |
| 6 | Boot line stdout | Eliminates Rich/stdout buffer race condition |
| 7 | 256-color gradient | Cobra `green_ramp` palette (22→46) |
| 8 | Progress pacing | Variable speed with `TimeElapsedColumn` |
| 9 | Percentage clamping | `_build_table` caps at 100% |
| 10 | ANSI sanitizer | Strips CSI/OSC/DCS from plugin output, preserves SGR |
| 11 | Stat fallback | Accurate dashboard even when Rich Live crashes |

---

## 📄 PDF Reports (v2.2.0)

Enterprise-grade reports signed by **[RET Tecnologia](https://rettecnologia.org)**, compliant with Brazilian and international frameworks:

| Section | Content |
|:---|:---|
| **Cover** | Logo, target, report ID (`CSR-YYYYMMDD-HHMMSS`), QR code → [rettecnologia.org](https://rettecnologia.org) |
| **Legal Disclaimers** | 12 frameworks: NDA, LGPD, Marco Civil, Art. 154-A, PL 4752/2025, ISO 27001, PCI DSS v4.0, NIST SP 800-115, OWASP Testing Guide v5, CVSS v4.0, SOC 2, HIPAA |
| **Executive Summary** | Dynamic severity posture badge with traffic-light scoring |
| **Risk Matrix** | 5×5 heat map with CVSS v4.0 color-coded severity |
| **Detailed Findings** | OWASP 2025 mapping, evidence, remediation steps |
| **Compliance Mapping** | 9 international frameworks with gap analysis |
| **Prioritized Remediation** | Findings sorted by CVSS score with effort estimates |
| **Glossary** | 20 security terms with definitions |
| **PTES Methodology** | 5-phase pentest documentation |
| **Revision History** | Version tracking with author and date |
| **Signature Page** | SHA-256 document integrity hash |

**Report features:** `"Página X de Y"` two-pass numbering · diagonal `CONFIDENCIAL` watermark · widows/orphans paragraph control · intelligent table splitting with `repeatRows=1` · clickable links to [rettecnologia.org](https://rettecnologia.org) on every page.

```bash
cascavel -t target.com --pdf       # Generate PDF report
cascavel -t target.com -o json     # JSON output for CI/CD pipelines
cascavel -t target.com -o md       # Markdown for documentation
```

---

## 🔌 Plugin Arsenal (84)

Zero false-positive tolerance. Standardized `run()` interface. Each plugin returns structured results with severity classification.

### 💉 Injection & Code Execution (7)

`xss_scanner` · `sqli_scanner` · `ssti_scanner` · `rce_scanner` · `blind_rce` · `nosql_scanner` · `cve_2021_44228_scanner`

### 🌐 Server-Side Attacks (4)

`ssrf_scanner` · `xxe_scanner` · `lfi_scanner` · `path_traversal`

### 🔐 Auth & Authorization (6)

`jwt_analyzer` · `oauth_scanner` · `csrf_detector` · `idor_scanner` · `session_fixation` · `password_policy`

### 🔄 Protocol-Level (4)

`http_smuggling` · `http2_smuggle` · `websocket_scanner` · `grpc_scanner`

### 🛡️ Defense Bypass (7)

`cors_checker` · `csp_bypass` · `clickjacking_check` · `host_header_injection` · `web_cache_poison` · `rate_limit_check` · `waf_bypass`

### 🎯 API Security (4)

`graphql_probe` · `graphql_injection` · `api_enum` · `api_versioning`

### 💣 Advanced Web (6)

`mass_assignment` · `race_condition` · `prototype_pollution` · `deserialization_scan` · `open_redirect` · `crlf_scanner`

### 🏗️ Infrastructure (8)

`docker_exposure` · `k8s_exposure` · `redis_unauth` · `mongodb_unauth` · `elastic_exposure` · `cicd_exposure` · `cloud_metadata` · `cloud_enum`

### 🔍 Recon & OSINT (11)

`subdomain_hunter` · `subdomain_takeou` · `dns_deep` · `dns_rebinding` · `network_mapper` · `email_harvester` · `email_spoof_check` · `shodan_recon` · `wayback_enum` · `whois_recon` · `traceroute_mapper`

### 🕵️ Info Gathering (7)

`tech_fingerprint` · `js_analyzer` · `param_miner` · `info_disclosure` · `secrets_scraper` · `git_dumper` · `admin_finder`

### 🌐 Web Scanning (7)

`dir_bruteforce` · `nikto_scanner` · `katana_crawler` · `http_methods` · `wps_scanmini` · `nuclei_scanner` · `fast_webshell`

### ☁️ Cloud (2)

`s3_bucket` · `saml_scanner`

### 📊 Analysis (5)

`ssl_check` · `waf_detec` · `profiler_bundpent` · `nmap_advanc` · `auto_exploit`

### 🔐 Brute Force (6)

`ssh_brute` · `ftp_brute` · `smb_ad` · `smpt_enum` · `heartbleed_scanner` · `domain_transf`

> 📖 Full documentation: [PLUGINS.md](PLUGINS.md)

---

## 💻 CLI Reference

```bash
python3 cascavel.py -t example.com           # Full scan (all plugins + tools)
python3 cascavel.py                           # Interactive mode
python3 cascavel.py -t example.com --pdf      # Generate PDF report
python3 cascavel.py -t example.com -o json    # JSON output (CI/CD integration)
python3 cascavel.py -t example.com -q         # Quiet mode (no animations)
python3 cascavel.py --plugins-only            # Skip external tools
python3 cascavel.py --list-plugins            # List all 84 plugins
python3 cascavel.py --check-tools             # Check installed tools
```

| Flag | Description |
|:---|:---|
| `-t TARGET` | Target domain or IP |
| `-q` | Suppress animations and preloader |
| `-o FORMAT` | Output format: `md` / `json` / `pdf` |
| `--pdf` | Shorthand for `-o pdf` |
| `--timeout N` | Per-tool timeout in seconds (default: 90) |
| `--plugins-only` | Run internal plugins only, skip external tools |
| `--check-tools` | Display status of 30+ external tools |
| `--list-plugins` | List all available plugins |
| `--no-preloader` | Skip cinematic boot animation |
| `--no-notify` | Disable desktop notifications |
| `-v` | Display version |

---

## 🛠️ External Tools (30+)

All optional — Cascavel auto-detects and skips missing tools gracefully.

| Category | Tools |
|:---|:---|
| **Recon** | subfinder · amass · dnsx · fierce · dnsrecon · whois |
| **Web Probing** | httpx · nikto · katana · feroxbuster · ffuf · gobuster |
| **Port Scanning** | nmap · naabu |
| **Vulnerability** | nuclei · sqlmap |
| **OSINT** | shodan · gau · waybackurls · asnmap · mapcidr |
| **WAF Detection** | wafw00f |
| **Network** | traceroute · dig · tshark |
| **Crypto/TLS** | sslscan |
| **CMS** | wpscan · whatweb |
| **Brute Force** | hydra · john |

> 💡 `install.sh` detects your OS and installs all available tools automatically.

---

## 🔒 Security Hardening

Cascavel is hardened against modern attack vectors targeting security tools themselves:

### Engine Protections

| Vector | Mitigation |
|:---|:---|
| **Terminal injection** (CSI/OSC/DCS) | `_sanitize_output()` strips dangerous ANSI escapes from all plugin output, preserving only SGR color codes |
| **Plugin timeout** | `SIGALRM`-based enforcement prevents plugins from hanging indefinitely |
| **Signal handler deadlock** | SIGINT handler uses `os.write()` (async-signal-safe) instead of `print()`/logging |
| **Process zombie leak** | `os.killpg()` kills entire process groups on timeout |
| **Input injection** | All external tool targets sanitized with `shlex.quote()` |

### Installer Protections (v2.3.0 — 15 hardenings)

| # | Vector | Mitigation |
|:--|:---|:---|
| 1 | **TOCTOU race** | `mktemp -d` for unique temporary directories |
| 2 | **Parallel execution** | Lock file + anti-symlink check prevents concurrent installs |
| 3 | **Supply chain** | SHA-256 hash verification on `requirements.txt` |
| 4 | **Known CVEs** | Version enforcement for 6 packages (PyJWT, ReportLab, requests, pyOpenSSL, dnspython) |
| 5 | **Permission escalation** | `umask 077`, `chmod 700/600` on sensitive files and directories |
| 6 | **Cleanup failure** | `trap` cleanup on EXIT/INT/TERM/HUP ensures temp removal |
| 7 | **PATH injection** | Strips `.` and relative paths from `$PATH` at startup |
| 8 | **Binary hijacking** | Uses absolute paths for `mkdir`, `rm`, `cat`, `date`, `uname` |
| 9 | **Container detection** | Detects Docker, Podman, LXC, cgroup-based containers |
| 10 | **WSL2 detection** | Identifies WSL kernel for network scan adjustments |
| 11 | **Stale venv** | Detects corrupted/moved Python binary and recreates venv |
| 12 | **SSL module check** | Verifies Python `ssl` module availability for pip HTTPS |
| 13 | **Locale enforcement** | Forces `LC_ALL=en_US.UTF-8` to prevent encoding bugs |
| 14 | **GOPATH validation** | Exports and validates `GOPATH/GOBIN` for Go tool installs |
| 15 | **Disk space check** | Warns if < 500MB available before starting install |

---

## 📁 Project Structure

```
Cascavel/
├── cascavel.py           # Core engine (2800+ lines)
├── report_generator.py   # PDF reports (ReportLab Platypus)
├── install.sh            # Universal installer (v2.3.0, 15 hardenings)
├── plugins/              # 84 security plugins
│   ├── xss_scanner.py    #   └── Standardized run() interface
│   ├── jwt_analyzer.py
│   └── ...
├── docs/                 # Screenshots and assets
├── reports/              # Generated reports (auto-created)
├── exports/              # Exported data (auto-created)
├── wordlists/            # Fuzzing wordlists
├── nuclei-templates/     # Custom Nuclei templates
├── requirements.txt      # Python dependencies
├── PLUGINS.md            # Full plugin documentation
├── CONTRIBUTING.md       # Contribution guide
├── CHANGELOG.md          # Version history
├── SECURITY.md           # Vulnerability disclosure policy
└── LICENSE               # MIT
```

---

## 🔄 CI/CD Security Pipeline (6 workflows)

Cascavel ships with **6 GitHub Actions workflows** enforcing security on every push and PR:

| Workflow | Jobs | Tools | Output |
|:---------|:-----|:------|:-------|
| [**CI**](.github/workflows/ci.yml) | Lint · Compile · Test · Security · Release Draft | Ruff 0.15.7 · py_compile · pytest · Bandit 1.9.4 | SARIF artifacts |
| [**Security CI**](.github/workflows/security.yml) | Syntax · Bandit SAST · Semgrep SAST · CVE Audit · Secrets | Bandit · Semgrep · pip-audit · Gitleaks | SARIF → Security Tab |
| [**CodeQL**](.github/workflows/codeql.yml) | Python semantic analysis | GitHub CodeQL | SARIF → Security Tab |
| [**Fuzzing**](.github/workflows/fuzz.yml) | Atheris fuzzing (100K runs) | Google Atheris (libFuzzer) | Crash detection |
| [**Scorecard**](.github/workflows/scorecard.yml) | OpenSSF supply-chain audit | OSSF Scorecard | Badge + SARIF |
| [**Dependabot**](.github/dependabot.yml) | Automated dependency updates | GitHub Dependabot | PRs for pip + actions |

> [!TIP]
> SARIF results from Bandit, Semgrep, CodeQL, and Scorecard appear directly in the **Security** tab — no extra dashboard needed.

> [!IMPORTANT]
> All GitHub Actions are **pinned by SHA** (not tag), and all workflows use **least-privilege `permissions: {}`** by default.

---

## ⚡ Signal Handling

Cascavel handles Unix signals for robust operation in all environments:

| Signal | Behavior | Use Case |
|:-------|:---------|:---------|
| `SIGINT` (Ctrl+C) | Async-signal-safe shutdown via `os.write()` → exit 130 | Interactive terminal |
| `SIGTERM` | Same handler → exit 143 | Docker/K8s graceful shutdown |
| `SIGPIPE` | Restored to `SIG_DFL` | Clean pipe termination (`\| head`) |
| `BrokenPipeError` | Caught + `os._exit(141)` | Fallback for SIGPIPE edge cases |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

**Plugin interface** — drop a file in `plugins/` and it's auto-discovered:

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """
    Args:
        target:     Domain or IP being scanned
        ip:         Resolved IPv4/IPv6 address
        open_ports: List of open port numbers (from naabu)
        banners:    Dict mapping port -> banner string
    
    Returns:
        {
            "plugin": "my_plugin",
            "resultados": [...],      # Findings list or summary string
            "severidade": "ALTO",     # CRITICO | ALTO | MEDIO | BAIXO | INFO
        }
    """
    return {"plugin": "my_plugin", "resultados": "Limpo", "severidade": "INFO"}
```

---

## 📋 Links

| Resource | Description |
|:---|:---|
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy (GPG key included) |
| [PLUGINS.md](PLUGINS.md) | Full plugin documentation, techniques, and bypass research |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guide with plugin interface spec |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant v2.1 |
| [LICENSE](LICENSE) | MIT License (SPDX: `MIT`) |
| [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/glferreira-devsecops/Cascavel) | Supply-chain security score |
| [OpenSSF Best Practices](https://www.bestpractices.dev/projects/12255) | Gold badge compliance |
| [RET Tecnologia](https://rettecnologia.org) | Company website |

---

<p align="center">
  <strong><code>MÉTODO CASCAVEL™</code></strong><br />
  <sub>
    A product of <a href="https://rettecnologia.org"><strong>RET Tecnologia</strong></a> — Engenharia de Software & Cibersegurança Ofensiva<br />
    <a href="https://github.com/glferreira-devsecops">Gabriel L. Ferreira</a> · Fundador & DevSecOps Lead
  </sub>
</p>

<p align="center">
  <a href="https://cascavel.pages.dev"><strong>🌐 cascavel.pages.dev</strong></a> · 
  <a href="https://rettecnologia.org"><strong>🏢 rettecnologia.org</strong></a>
</p>

<p align="center">
  <sub>Making the web safer, one target at a time. 🐍</sub>
</p>