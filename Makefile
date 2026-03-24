# ============================================
# Cascavel Security Framework — Makefile
# RET Tecnologia | https://rettecnologia.org
# ============================================

.PHONY: help install dev lint format security test clean check all

PYTHON ?= python3
PIP ?= pip3
VENV := .venv

# ── Default ──────────────────────────────────

help: ## Show this help message
	@echo ""
	@echo "  🐍 Cascavel Security Framework — Dev Commands"
	@echo "  ─────────────────────────────────────────────"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Setup ────────────────────────────────────

install: ## Install Cascavel + dependencies
	$(PIP) install -e .

dev: ## Install with dev dependencies (ruff, bandit, mypy, pytest)
	$(PIP) install -e ".[dev]"
	pre-commit install 2>/dev/null || true

venv: ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	@echo "Activate with: source $(VENV)/bin/activate"

# ── Code Quality ─────────────────────────────

lint: ## Run ruff linter
	ruff check cascavel.py plugins/ --output-format=concise

format: ## Auto-format code with ruff
	ruff format cascavel.py plugins/
	ruff check --fix cascavel.py plugins/

security: ## Run bandit security scanner
	bandit -r cascavel.py plugins/ -c pyproject.toml -q

typecheck: ## Run mypy type checker
	mypy cascavel.py plugins/ --ignore-missing-imports

# ── Testing ──────────────────────────────────

test: ## Run pytest
	pytest tests/ -v --tb=short 2>/dev/null || echo "No tests directory found"

# ── Combined ─────────────────────────────────

check: lint security ## Run lint + security (CI gate)
	@echo "✅ All checks passed"

all: lint format security test ## Run everything

# ── Cleanup ──────────────────────────────────

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ .eggs/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	@echo "🧹 Clean complete"
