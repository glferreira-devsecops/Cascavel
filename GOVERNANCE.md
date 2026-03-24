# Governance — Cascavel Security Framework

> An open-source product by [RET Tecnologia](https://rettecnologia.org)

## Overview

Cascavel is maintained under a **BDFL (Benevolent Dictator for Life)** governance model, where the project founder retains final decision-making authority while actively encouraging community participation.

## Roles

### 🎯 Project Lead (BDFL)

**Gabriel Ferreira** ([@glferreira-devsecops](https://github.com/glferreira-devsecops))

- Final authority on architectural decisions
- Merge approval for all pull requests
- Release management and versioning
- Security vulnerability triage

### 🛡️ Maintainers

Individuals granted write access to the repository. Maintainers can:

- Review and approve pull requests
- Triage issues and apply labels
- Manage CI/CD workflows
- Mentor new contributors

### 🤝 Contributors

Anyone who submits a pull request, reports a bug, improves documentation, or participates in discussions. Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Decision Making

1. **Issues First** — All significant changes start as a GitHub Issue
2. **Discussion** — Community feedback is gathered via issue comments or GitHub Discussions
3. **Pull Request** — Implementation follows the [Contributing Guide](CONTRIBUTING.md)
4. **Review** — At least one maintainer review is required
5. **Merge** — The Project Lead or a designated maintainer merges approved PRs

### Breaking Changes

Changes that modify the public API, plugin interface, or CLI behavior require:

- An issue labeled `breaking`
- A minimum 7-day discussion period
- Explicit approval from the Project Lead
- A CHANGELOG entry under `### Changed` or `### Removed`

## Contributions

We welcome contributions of all kinds:

- 🐛 Bug reports and fixes
- ✨ New security plugins
- 📝 Documentation improvements
- 🌐 Translations
- 🧪 Test coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Code of Conduct

All participants must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing

Cascavel is licensed under the [MIT License](LICENSE). By contributing, you agree that your contributions will be licensed under the same terms.

---

<p align="center">
  <sub>Maintained by <a href="https://rettecnologia.org">RET Tecnologia</a> — Building the future of offensive security tools.</sub>
</p>
