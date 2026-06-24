# 🏗️ Cascavel Architecture

## Overview

Cascavel v3.0 is a modular CTEM (Continuous Threat Exposure Management) engine with 135+ plugins.

```
cascavel/
├── __init__.py          # Package marker, exports __version__
├── __main__.py          # CLI entry point, argument parsing, scan orchestration
├── security.py          # ANSI sanitizer, signal handling, output hardening
├── constants.py         # Paths, style constants, version, severity maps
├── validators.py        # Target validation (SSRF blocklist, IP normalization, IDNA)
├── tools.py             # External tool detection, execution, wordlists
├── engine.py            # Plugin engine, baselines, classification, live display
├── reporters.py         # Report generation (MD, JSON)
├── ui.py                # UI components (banner, preloader, dashboard, notifications)
├── updater.py           # Self-update, global install, version check
├── preflight.py         # Pre-flight system checks
├── threat_intel.py      # EPSS/CISA KEV enrichment
├── ai_remediation.py    # AI-driven remediation scripts
├── sarif_exporter.py    # SARIF v2.1.0 export
├── ocsf_exporter.py     # OCSF v1.1.0 export
├── report_generator.py  # PDF report generation
├── plugins/             # 135+ security plugins
│   ├── __init__.py
│   ├── schema.py        # Plugin schema validation
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── ... (135+ plugins)
│   ├── supply_chain_scan.py    # NEW: Supply chain security
│   ├── secrets_deep_scan.py    # NEW: Deep secrets scanning
│   ├── container_escape.py     # NEW: Container escape detection
│   ├── cloud_exploitation.py   # NEW: Cloud exploitation
│   ├── ad_detection.py         # NEW: Active Directory detection
│   ├── adversary_simulation.py # NEW: MITRE ATT&CK simulation
│   ├── mobile_apk_scan.py      # NEW: Mobile app scanning
│   ├── firmware_analysis.py    # NEW: Firmware analysis
│   ├── fuzzing_engine.py       # NEW: Advanced fuzzing
│   ├── http3_test.py           # NEW: HTTP/3/QUIC testing
│   ├── wireless_audit.py       # NEW: Wireless auditing
│   ├── mitm_framework.py       # NEW: MITM testing
│   ├── printer_exploit.py      # NEW: Printer exploitation
│   ├── osint_deep.py           # NEW: Deep OSINT
│   ├── api_fuzzing.py          # NEW: API security testing
│   ├── dns_recon_deep.py       # NEW: Advanced DNS recon
│   ├── subdomain_takeover.py   # NEW: Subdomain takeover
│   ├── privilege_escalation.py # NEW: Privilege escalation
│   ├── persistence_check.py    # NEW: Persistence detection
│   ├── cobalt_strike_c2.py     # NEW: C2 detection
│   ├── phishing_simulation.py  # NEW: Phishing testing
│   ├── wifi_rogue_ap.py        # NEW: Rogue AP detection
│   ├── firmware_emulation.py   # NEW: Firmware emulation
│   ├── bluetooth_audit.py      # NEW: Bluetooth security
│   ├── blockchain_audit.py     # NEW: Web3/Blockchain
│   ├── ics_scada.py            # NEW: ICS/SCADA security
│   └── zero_trust_validate.py  # NEW: Zero Trust validation
├── profiles/            # Scan profiles (YAML)
│   ├── web.yaml
│   ├── api.yaml
│   ├── cloud.yaml
│   ├── network.yaml
│   └── full.yaml
├── docs/                # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEVELOPER.md
│   ├── PLUGIN_GUIDE.md
│   └── DTO.md
├── tests/               # Test suite
├── wordlists/           # Wordlists (auto-downloaded)
└── nuclei-templates/    # Nuclei templates (auto-updated)
```

## Module Dependencies

```
__main__.py
├── validators.py    (no deps)
├── tools.py         (constants)
├── engine.py        (constants, security)
├── ui.py            (engine, constants)
├── reporters.py     (constants)
├── updater.py       (constants)
├── preflight.py     (engine, tools, constants)
├── threat_intel.py  (standalone)
└── ai_remediation.py (standalone)
```

## Data Flow

```
CLI Input
    │
    ▼
validate_target() ─── SSRF blocklist, IP normalization, DNS rebinding guard
    │
    ▼
detect_tools() ─────── Parallel tool detection (ThreadPoolExecutor)
    │
    ▼
enum_tools() ───────── External tools pipeline (nmap, nuclei, ffuf, etc)
    │
    ▼
run_plugins() ──────── Plugin engine with live split-screen display
    │                   ├── _exec_plugin() per plugin (SIGALRM timeout)
    │                   ├── _classify() → vuln/erro/limpo
    │                   └── _count_sev() → CRITICO/ALTO/MEDIO/BAIXO/INFO
    ▼
enrich_results() ───── EPSS/CISA KEV threat intel enrichment
    │
    ▼
generate_ai_fixes() ── AI remediation (optional)
    │
    ▼
save_report() ──────── MD/JSON/PDF/SARIF/OCSF export
    │
    ▼
print_dashboard() ──── Final mission report with severity breakdown
```

## Plugin Interface

Every plugin must implement:

```python
def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
```

### Parameters
- `target`: Target hostname/IP
- `ip`: Resolved IP address
- `ports`: List of open ports
- `banners`: Port banners {port: banner_string}
- `context`: Global context dict with:
  - `baseline_latency`: Average response time
  - `baseline_404_len`: Average 404 response length
  - `discovered_params`: List of discovered parameters
  - `oob_server`: OOB interaction server

### Return Format
```python
{
    "plugin": "plugin_name",
    "resultados": [
        {
            "nome": "Vulnerability Name",
            "descricao": "Description",
            "severidade": "CRITICO|ALTO|MEDIO|BAIXO|INFO",
            "evidencia": "Evidence",
            "correcao": "Remediation advice"
        }
    ]
}
```

## Security Model

1. **Target Validation**: 50+ edge cases (SSRF, DNS rebinding, IDNA homograph)
2. **Output Sanitization**: ANSI escape injection prevention (CWE-117)
3. **Plugin Isolation**: SIGALRM timeout per plugin (120s default)
4. **Signal Safety**: os.write() for signal handlers (async-signal-safe)
5. **Path Traversal**: _safe_join() protection in reporters
6. **Command Injection**: shlex.quote() for all external tool invocations

## Scan Profiles

YAML-based profiles select which plugins to run:

```yaml
name: web
description: Web application security scan
plugins:
  - xss_scanner
  - sqli_scanner
  - csrf_detector
  - cors_checker
  - security_headers
  # ... more plugins
```

Built-in profiles: `web`, `api`, `cloud`, `network`, `full`
