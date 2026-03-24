# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-03-24

### Added
- **`--quiet` (`-q`) flag** — Suppress all animations, preloader, and banner for CI/CD use
- **`--output-format json` (`-o json`)** — Export structured JSON reports with severity counts
- **`--timeout N` flag** — Custom global timeout for external tools (default: 90s)
- **TTY detection** — Automatically disables animations when stdout is not a terminal (pipe/redirect)
- **JSON report engine** — `save_json_report()` with target, IP, timestamp, severity aggregation
- **CHANGELOG.md** — This file
- **CLI examples in help text** — `cascavel -h` now shows practical usage examples

### Changed
- **`fast_webshell.py`** — Converted from active webshell upload to passive PUT/PATCH method detection (zero false positives, zero malicious payload)
- **`cve_2021_44228_scanner.py`** — Rewritten with 12 HTTP header injection vectors, 5 WAF bypass payloads, Java/Spring/Tomcat fingerprinting, and timeout anomaly detection
- **README.md** — Complete rewrite for open-source release (badges, architecture diagram, CLI reference, collapsible install guides)
- **PLUGINS.md** — Updated with accurate plugin count and categories
- **pyproject.toml** — Bumped to v2.1.0, removed unused deps (colorama, termcolor), added Windows classifier
- **requirements.txt** — Cleaned unused dependencies, reorganized by category
- **.gitignore** — Added `*.egg-info/`, `dist/`, `build/`, `wordlists/*.txt`
- **Typewriter effect** — Falls back to direct print when stdout is not a TTY
- **Report encoding** — `save_report()` now uses `encoding="utf-8"` explicitly
- **Boot sequence** — Version string is now dynamic (`f"v{__version__}"`)

### Removed
- **`colorama`** — Unused (Rich handles all terminal output)
- **`termcolor`** — Unused (Rich handles all terminal output)

### Deprecated
- **`wifi_attac.py`** — Stub scheduled for removal (Cascavel focuses on web/URL, Wi-Fi is out of scope)
- **`aws_keyhunter.py`** — Functionality absorbed by `secrets_scraper.py`

---

## [2.0.0] - 2026-03-23

### Added
- **26 new security plugins** bringing total to 84:
  - HTTP Smuggling (H2.O, CL-TE, TE-CL, HTTP/2)
  - gRPC scanner (reflection, insecure channel)
  - OAuth scanner (PKCE, state, token leak)
  - Kubernetes exposure (API, etcd, kubelet)
  - CI/CD exposure (Jenkins, GitLab CI, GitHub Actions)
  - Race condition detector
  - Mass assignment scanner
  - SAML scanner (signature wrapping, assertion)
  - API versioning (deprecated endpoint detection)
  - DNS rebinding scanner
  - Session fixation detector
  - WebSocket scanner (CSWSH, origin bypass)
  - Blind RCE (time-based OOB)
  - Open redirect scanner
  - CRLF injection scanner
  - Prototype pollution scanner
  - Web cache poisoning
  - Rate limit checker
  - NoSQL injection scanner
  - CSP bypass analyzer
  - Graph QL injection (batching, introspection)
  - WAF bypass (encoding, chunked, case mutation)
  - Host header injection
  - Password policy analyzer
  - Cloud enumeration (AWS/GCP/Azure)
  - Traceroute mapper with CDN/ISP detection
- **WHOIS/RDAP deep reconnaissance plugin** — domain age, registrar risk, privacy detection, DNSSEC, expiry monitoring
- **Cinematic preloader** — ASCII cobra animation, typewriter boot sequence
- **Security Intel panel** — Random security facts during plugin execution
- **Live progress dashboard** — Split-screen results table + intel panel
- **Plugin versioning** — `versao` and `tecnicas` keys in plugin output

### Changed
- **52 existing plugins** rewritten with 2026-grade intelligence (modern payloads, bypass techniques)
- **32+ command injection vulnerabilities remediated** — `shlex.quote()` applied across all plugins
- **Report engine** — Severity-based classification (CRITICO/ALTO/MEDIO/BAIXO/INFO)
- **`run_cmd()`** — All targets pre-sanitized with `shlex.quote()`
- **External tool pipeline** — Graceful degradation when tools are not installed

### Security
- Remediated all command injection vectors in subprocess calls
- All external tool inputs sanitized via `shlex.quote()`
- Timeouts enforced on all `subprocess.run()` and `requests` calls

---

## [1.0.0] - 2025-01-01

### Added
- Initial release
- Core plugin engine with auto-discovery
- External tools integration (nmap, nikto, nuclei, subfinder, httpx)
- Markdown report generation
- Desktop notifications via notify-py
- ~60 security plugins

---

> **Note**: Dates for v1.0.0 and v2.0.0 are approximate.
