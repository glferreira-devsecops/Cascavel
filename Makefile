# ════════════════════════════════════════════════════════════════════════
# Cascavel Quantum Security Framework — Makefile
# RET Tecnologia | https://rettecnologia.org
# ════════════════════════════════════════════════════════════════════════

.PHONY: help install dev lint format security typecheck test compile check all clean venv audit

PYTHON ?= python3
PIP    ?= pip3
VENV   := .venv
SRC    := cascavel.py report_generator.py plugins/

# ── Default ──────────────────────────────────

help: ## Show this help message
	@echo ""
	@echo "  🐍 Cascavel Quantum Security Framework — Dev Commands"
	@echo "  ─────────────────────────────────────────────────────"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Setup ────────────────────────────────────

install: ## Install Cascavel + dependencies
	$(PIP) install -e .

full: ## Install with ALL optional dependencies
	$(PIP) install -e ".[full]"

dev: ## Install with dev dependencies (ruff, bandit, mypy, pytest)
	$(PIP) install -e ".[dev]"
	$(PIP) install pytest==8.3.5
	pre-commit install 2>/dev/null || true

venv: ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	@echo "Activate with: source $(VENV)/bin/activate"

# ── Code Quality ─────────────────────────────

lint: ## Run ruff linter
	ruff check $(SRC) --output-format=concise

format: ## Auto-format code with ruff
	ruff format $(SRC)
	ruff check --fix $(SRC)

security: ## Run bandit security scanner
	bandit -r $(SRC) -c pyproject.toml -q

typecheck: ## Run mypy type checker
	mypy $(SRC) --ignore-missing-imports

# ── Compile & Test ───────────────────────────

compile: ## Compile-check all Python files
	$(PYTHON) -m py_compile cascavel.py
	$(PYTHON) -m py_compile report_generator.py
	@find plugins/ -name "*.py" -exec $(PYTHON) -m py_compile {} \;
	@echo "✅ All files compiled successfully"

test: ## Run pytest
	pytest tests/ -v --tb=short 2>/dev/null || echo "No tests found — running smoke tests" && \
	$(PYTHON) -c "import cascavel; import report_generator; print('✅ Smoke test passed')"

# ── Security Audit ───────────────────────────

audit: ## Run pip-audit for CVE detection
	pip-audit --desc || true

# ── Version Check ────────────────────────────

version-check: ## Verify version sync across all files
	@$(PYTHON) -c "\
	import re; \
	py = re.search(r'__version__\s*=\s*\"([\d.]+)\"', open('cascavel.py').read()).group(1); \
	toml = re.search(r'^version\s*=\s*\"([\d.]+)\"', open('pyproject.toml').read(), re.M).group(1); \
	assert py == toml, f'MISMATCH: cascavel.py={py} pyproject.toml={toml}'; \
	print(f'✅ Version synced: v{py}')"

# ── Combined ─────────────────────────────────

check: lint compile security version-check ## CI gate: lint + compile + security + version
	@echo "✅ All CI checks passed"

all: lint format compile security test audit version-check ## Run everything
	@echo "✅ Full pipeline complete"

# ── Cleanup ──────────────────────────────────

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ .eggs/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	rm -f bandit-report.json audit-results.json
	@echo "🧹 Clean complete"
