# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Cascavel framework, we appreciate your help in disclosing it responsibly.

### How to Report

1. **Preferred**: Open a private security advisory on [GitHub](https://github.com/glferreira-devsecops/Cascavel/security/advisories).
2. **Alternative**: Contact the maintainer **DevFerreiraG** via [LinkedIn](https://www.linkedin.com/in/DevFerreiraG) or email at `devferreirag@proton.me`.
3. **Please include**:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Impact assessment and severity rating
   - Suggested fix (if applicable)
4. **Please avoid** publicly disclosing the issue until we have addressed it.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | ✅ Full   |
| 2.0.x   | ✅ Full   |
| 1.x     | ⚠️ Critical fixes only |

## Response

We aim to respond within **48 hours** and patch valid issues within **7 business days**.

## Scope

This security policy covers:

- `cascavel.py` — Core engine
- All files in `plugins/` — Security plugins
- `wordlists/` — Bundled wordlists
- Configuration files (`pyproject.toml`, `requirements.txt`)

### Out of Scope

- Third-party tools integrated by the framework (nmap, nuclei, etc.) have their own security policies
- Vulnerabilities in Python dependencies should be reported to the respective projects

## Ethical Use

Cascavel is designed for **authorized security testing only**. Using this tool against systems without proper authorization is illegal and unethical. The maintainers are not responsible for any misuse.
