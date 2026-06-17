# Roadmap — Cascavel Security Framework

> An open-source product by [RET Tecnologia](https://rettecnologia.org)

This document outlines the planned direction for Cascavel. It is a living document and may change based on community feedback, security landscape shifts, and contributor availability.

## Current — v3.0.1 (Stable)

✅ 85+ security plugins with 2026-grade intelligence
✅ JSON + Markdown + **PDF** report generation
✅ Cinematic terminal UX with TTY detection
✅ `--quiet` mode for CI/CD integration
✅ Comprehensive installer with 15+ edge case checks
✅ Full open-source governance (CITATION, FUNDING, CODEOWNERS)
✅ **Plugin API v2** — Standardized return schema with CVSS v4.0 scoring
✅ **SARIF v2.1.0 output** — IDE + CI/CD integration (GitHub, VSCode, Azure DevOps)
✅ **Pytest test suite** — 211 tests (plugin discovery, schema validation, silent failure coverage)
✅ **Docker multi-stage image** — Go tools (nuclei, subfinder, katana) + system tools (nmap, nikto)
✅ **Scan profiles (YAML)** — Pre-configured profiles: web, api, cloud, network, full
✅ **Python 3.10+ baseline** — Modern type syntax, TaskGroup readiness
✅ **Silent failure hardening** — `SILENT_ERROR` reporting across all critical plugins
✅ **Manual dependency control** — No automated dependency bots (supply chain security)

## Short-Term — v3.1.0 (Q3 2026)

- [ ] **Async plugin engine** — `asyncio`-based execution for 3-5x speed improvement
- [ ] **Man page** — `man cascavel` via `pyproject.toml`
- [ ] **Internationalization (i18n)** — English plugin output (Portuguese kept as default)
- [ ] **Official Docker registry** — `ghcr.io/glferreira-devsecops/cascavel` published image
- [ ] **Plugin migration** — Convert top 20 critical plugins to `PluginResult` schema
- [ ] **CLI --sarif/--profile integration tests** — E2E validation in CI pipeline

## Medium-Term — v4.0.0 (Q1 2027)

- [ ] **Plugin marketplace** — Community-submitted plugins via separate repo
- [ ] **API mode** — REST API server (`cascavel --serve`) for integration with SOAR platforms
- [ ] **SBOM generation** — Software Bill of Materials based on scan results
- [ ] **GitHub App** — One-click security audit from PR comments

## Long-Term — v4.0.0 (2027)

- [ ] **AI-assisted triage** — LLM-powered severity classification and remediation hints
- [ ] **Distributed scanning** — Multi-node scan execution for large-scope engagements
- [ ] **Compliance mapping** — Auto-map findings to OWASP Top 10, NIST, PCI-DSS, CIS

## How to Contribute

Want to help shape the future of Cascavel?

1. **Vote on issues** — Use 👍 reactions on issues you want prioritized
2. **Discuss ideas** — Open a [Feature Request](https://github.com/glferreira-devsecops/Cascavel/issues/new?template=feature_request.yml)
3. **Submit PRs** — Check issues labeled [`good first issue`](https://github.com/glferreira-devsecops/Cascavel/labels/good%20first%20issue) or [`help wanted`](https://github.com/glferreira-devsecops/Cascavel/labels/help%20wanted)
4. **Read the Contributing Guide** — [CONTRIBUTING.md](CONTRIBUTING.md)

---

<p align="center">
  <sub>Maintained by <a href="https://rettecnologia.org">RET Tecnologia</a> — Building the future of offensive security tools.</sub>
</p>
