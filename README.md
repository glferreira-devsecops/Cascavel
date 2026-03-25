<p align="center">
  <img src="docs/cascavel_banner.png" alt="Cascavel" width="800" />
</p>

<h1 align="center">
  <code>🐍 CASCAVEL</code>
</h1>

<h3 align="center">Quantum Security Framework — Red Team Intelligence Engine</h3>

<p align="center">
  <strong>85 security plugins · 30+ recon tools · CLI-first · Cross-platform · PDF reports</strong><br />
  One command to enumerate, scan, attack, analyze, and generate enterprise-grade pentest reports.
</p>

<p align="center">
  🇺🇸 <strong>English</strong> ·
  <a href="README.pt-BR.md">🇧🇷 Português (Brasil)</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF.svg?style=flat-square" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white" /></a>
  <img src="https://img.shields.io/badge/Plugins-85-blueviolet.svg?style=flat-square" />
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
  <a href="#-install">Install</a> · 
  <a href="#-what-makes-cascavel-different">Why Cascavel</a> · 
  <a href="#-architecture">Architecture</a> · 
  <a href="#-plugin-arsenal-85">Plugins</a> · 
  <a href="#-cli-reference">CLI</a> · 
  <a href="#-pdf-reports">Reports</a> · 
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
| **Unified pipeline** | 85 plugins + 30 tools in one command | Fragmented scripts |
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
| **Python** | 3.8+ | f-strings, `importlib.util`, `shlex.quote` |
| **PyJWT** | 2.12.0 | CVE-2022-29217 — algorithm confusion attack |
| **ReportLab** | 3.6.13 | CVE-2023-33733 — code execution via crafted PDF |
| **Requests** | 2.31.0 | CVE-2023-32681 — header leak on redirect |

> [!NOTE]
> The installer automatically enforces these minimum versions. Manual installs should verify with `pip list`.

**One command — works on macOS, Linux (Debian/Ubuntu/Kali/Parrot/Fedora/Arch/Alpine/SUSE), and WSL:**

```bash
curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/Cascavel/main/install.sh | bash
```

The installer v2.2.0 includes **12 security hardenings**: `trap` cleanup, `mktemp` isolation, install lock, SHA-256 hash verification, CVE checks on critical dependencies (PyJWT ≥2.12.0, ReportLab ≥3.6.13, Requests ≥2.31.0), umask 077, and strict file permissions.

<details>
<summary><strong>Manual installation</strong></summary>

```bash
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 cascavel.py -t target.com
```

</details>

---

## 🏗️ Architecture

```
cascavel.py (1700+ lines)
├── ANSI Escape Sanitizer ──── Blocks CSI/OSC/DCS injection from plugins
├── Preloader Engine ────────── 4-phase cinematic boot (logo fade → boot seq → progress → online)
├── Plugin Orchestrator ──────── Dynamic loading, timeout (SIGALRM), output sanitization
├── Split-Screen Dashboard ──── Rich Live layout (scan table + security intel panel)
├── External Tools Pipeline ── 30+ tools with shlex.quote() safety
├── Report Engine ───────────── PDF (ReportLab Platypus), Markdown, JSON
└── Signal Handler ──────────── Async-signal-safe SIGINT (os.write, no deadlocks)
```

### Terminal UX Engine (21 Hardenings)

| Protection | What it does |
|:---|:---|
| `_get_terminal_height()` | POSIX fallback for headless/pipe terminals |
| `_fade_in_logo` term detection | Skips cursor manipulation on terminals < 20 rows |
| `_clear_block` safety clamp | Never moves cursor beyond terminal boundaries |
| `run_preloader` try/except wrapper | Graceful fallback for CI/pipe/dumb terminals |
| `_typewriter` KeyboardInterrupt | Guarantees newline before SIGINT propagation |
| `_boot_line` unified stdout | Eliminates Rich/stdout buffer race condition |
| Cobra `green_ramp` palette | True 256-color green gradient (22→46) |
| Progress bar variable speed | Comfortable 2s pacing with `TimeElapsedColumn` |
| `_build_table` pct max 100 | Prevents >100% display on final iteration |
| ANSI escape sanitizer | Blocks CSI/OSC/DCS terminal injection from plugins |
| Fallback stat tracking | Accurate dashboard even when Live layout crashes |

---

## 📄 PDF Reports

Enterprise-grade reports signed by **RET Tecnologia**, compliant with Brazilian and international frameworks:

- **Cover** — logo, target, report ID, confidentiality classification
- **12 legal disclaimers** — NDA, LGPD, Marco Civil, Art. 154-A, Bill 4752/2025, ISO 27001, PCI DSS v4.0, NIST SP 800-115, OWASP Testing Guide, CVSS v4.0
- **Executive summary** — dynamic severity posture badge
- **CVSS v4.0 scoring** — color-coded severity table with risk matrix
- **Detailed findings** — OWASP mapping, evidence, remediation steps
- **Compliance mapping** — 9 international frameworks
- **PTES methodology** — 5-phase pentest documentation
- **Signature page** — SHA-256 integrity hash

```bash
python3 cascavel.py -t target.com --pdf    # Generate PDF
python3 cascavel.py -t target.com -o json  # JSON for CI/CD
```

---

## 🔌 Plugin Arsenal (85)

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

### 🔐 Brute Force (7)

`ssh_brute` · `ftp_brute` · `smb_ad` · `smpt_enum` · `heartbleed_scanner` · `domain_transf` · `dns_zone_transfer`

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
python3 cascavel.py --list-plugins            # List all 85 plugins
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

### Installer Protections (v2.2.0)

| Vector | Mitigation |
|:---|:---|
| **TOCTOU race** | `mktemp -d` for temporary directories |
| **Parallel execution** | Lock file prevents concurrent installs |
| **Supply chain** | SHA-256 hash verification on `requirements.txt` |
| **Known CVEs** | Version checks for PyJWT, ReportLab, Requests |
| **Permission escalation** | `umask 077`, `chmod 700/600` on sensitive paths |
| **Cleanup failure** | `trap` ensures temp directory removal on exit/error |

---

## 📁 Project Structure

```
Cascavel/
├── cascavel.py           # Core engine (1700+ lines)
├── report_generator.py   # PDF reports (ReportLab Platypus)
├── install.sh            # Universal installer (v2.2.0, 12 hardenings)
├── plugins/              # 85 security plugins
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

## 🔄 CI/CD Security Pipeline

Cascavel ships with a [GitHub Actions workflow](.github/workflows/security.yml) that enforces security on every push and PR:

| Job | Tool | Output |
|:----|:-----|:-------|
| **Syntax Check** | `py_compile` | Validates all `.py` files |
| **SAST (Bandit)** | [Bandit](https://github.com/PyCQA/bandit) | SARIF → GitHub Security Tab |
| **SAST (Semgrep)** | [Semgrep](https://semgrep.dev) | Rules: `auto` + `python` + `owasp-top-ten` |
| **CVE Audit** | `pip-audit` | Enforces PyJWT/ReportLab/Requests minimums |
| **Secret Detection** | [Gitleaks](https://github.com/gitleaks/gitleaks) | Full commit history scan |

> [!TIP]
> SARIF results appear directly in the **Security** tab of your GitHub repo — no extra dashboard needed.

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
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |
| [PLUGINS.md](PLUGINS.md) | Full plugin documentation and techniques |
| [LICENSE](LICENSE) | MIT License |

---

<p align="center">
  <strong><code>MÉTODO CASCAVEL™</code></strong><br />
  <sub>
    <a href="https://rettecnologia.org"><strong>RET Tecnologia</strong></a> — Engenharia de Software & Cibersegurança Ofensiva<br />
    <a href="https://github.com/glferreira-devsecops">Gabriel L. Ferreira</a> · Fundador & DevSecOps Lead
  </sub>
</p>

<p align="center">
  <sub>Making the web safer, one target at a time. 🐍</sub>
</p>