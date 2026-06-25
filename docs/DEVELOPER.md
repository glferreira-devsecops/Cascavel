# 👨‍💻 Developer Guide

## Setup

```bash
# Clone
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel

# Install dependencies
pip install -r requirements.txt

# Install with dev dependencies
pip install -e ".[dev]"

# Run
python -m cascavel --help
```

## Project Structure

| Module | Responsibility | Lines |
|---|---|---|
| `__main__.py` | CLI entry point, scan orchestration | ~300 |
| `security.py` | ANSI sanitizer, signal handling | ~80 |
| `constants.py` | Paths, styles, version | ~40 |
| `validators.py` | Target validation | ~200 |
| `tools.py` | External tool pipeline | ~250 |
| `engine.py` | Plugin engine, live display | ~350 |
| `reporters.py` | Report generation | ~60 |
| `ui.py` | UI components | ~350 |
| `updater.py` | Self-update | ~100 |
| `preflight.py` | System checks | ~80 |

## Adding a New Plugin

1. Create `plugins/my_plugin.py`:

```python
"""
My Plugin — Description of what it tests
"""
from typing import Any


def run(target: str, ip: str, ports: list[int], banners: dict[str, str], context: dict | None = None) -> dict[str, Any] | None:
    """Main plugin entry point."""
    findings = []

    # Your security tests here
    try:
        import requests
        resp = requests.get(f"http://{target}/test", timeout=5)
        if "vulnerable" in resp.text:
            findings.append({
                "nome": "My Vulnerability",
                "descricao": "Found vulnerable endpoint",
                "severidade": "ALTO",
                "evidencia": resp.text[:200],
                "correcao": "Apply patch XYZ"
            })
    except Exception:
        pass

    if findings:
        return {"plugin": "my_plugin", "resultados": findings}
    return None
```

2. Test it:
```bash
python -m cascavel -t example.com --plugin-filter my_plugin --plugins-only
```

## Plugin Best Practices

- **Always use timeouts** in HTTP requests (5-10s default)
- **Handle exceptions gracefully** — return None on failure
- **Use context** for baseline-aware testing
- **Return structured findings** with severity levels
- **Include remediation advice** in every finding
- **Keep it focused** — one vulnerability class per plugin

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=cascavel

# Specific test
pytest tests/test_core.py
```

## Code Quality

```bash
# Lint
ruff check .

# Format
ruff format .

# Type check
mypy cascavel/

# Security scan
bandit -r cascavel/
semgrep --config=auto cascavel/
```

## Release Process

1. Update `__version__` in `constants.py`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v3.1.0`
4. Push: `git push origin main --tags`
5. GitHub Actions builds and publishes release

## Architecture Decisions

### Why monolith → modules?
- Original `cascavel.py` was 3519 lines
- Modules enable independent testing
- Clear separation of concerns
- Easier onboarding for contributors

### Why SIGALRM for plugin timeout?
- Per-plugin isolation prevents hung plugins from blocking scan
- Signal-safe (no threading complexity)
- 120s default covers most network operations

### Why Rich for UI?
- Cross-platform terminal rendering
- Live display with Layout for split-screen
- Progress bars, tables, panels
- Graceful degradation for non-TTY

### Why shlex.quote() for external tools?
- Prevents command injection
- All targets are user-controlled
- shell=True is necessary for pipe chains
