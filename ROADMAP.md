# Roadmap — Cascavel Security Framework

> An open-source product by [RET Tecnologia](https://rettecnologia.org)

This document outlines the planned direction for Cascavel. It is a living document and may change based on community feedback, security landscape shifts, and contributor availability.

## Current — v2.1.0 (Stable)

✅ 85+ security plugins with 2026-grade intelligence
✅ JSON + Markdown report generation
✅ Cinematic terminal UX with TTY detection
✅ `--quiet` mode for CI/CD integration
✅ Comprehensive installer with 15+ edge case checks
✅ Full open-source governance (CITATION, FUNDING, CODEOWNERS)

## Short-Term — v2.2.0 (Q2 2026)

- [ ] **Plugin API v2** — Standardized return schema with CVSS scoring
- [ ] **SARIF output** — Static Analysis Results Interchange Format for IDE integration
- [ ] **Plugin test suite** — Pytest framework for individual plugin validation
- [ ] **Docker image** — Official `ghcr.io/glferreira-devsecops/cascavel` container
- [ ] **Man page** — `man cascavel` via `setup.py` / `pyproject.toml`
- [ ] **Internationalization (i18n)** — English plugin output (Portuguese kept as default)

## Medium-Term — v3.0.0 (Q4 2026)

- [ ] **Async plugin engine** — `asyncio`-based execution for 3-5x speed improvement
- [ ] **Plugin marketplace** — Community-submitted plugins via separate repo
- [ ] **API mode** — REST API server (`cascavel --serve`) for integration with SOAR platforms
- [ ] **Custom scan profiles** — YAML-based target profiles (web, api, cloud, network)
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
