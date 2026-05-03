# ============================================
# Cascavel Security Framework — Makefile
# RET Tecnologia | https://rettecnologia.org
# v3.0.0 — Complete development workflow
# ============================================

.PHONY: help install dev lint format security typecheck test test-cov docker docker-run clean check all profiles sarif-validate

PYTHON ?= python3
PIP ?= pip3
VENV := .venv
SRC := cascavel.py sarif_exporter.py report_generator.py
DIRS := plugins/ tests/

# ── Default ──────────────────────────────────

help: ## Show this help message
	@echo ""
	@echo "  🐍 Cascavel Security Framework — Dev Commands"
	@echo "  ─────────────────────────────────────────────"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
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

lint: ## Run ruff linter on all sources
	ruff check $(SRC) $(DIRS) --output-format=concise

format: ## Auto-format code with ruff
	ruff format $(SRC) $(DIRS)
	ruff check --fix $(SRC) $(DIRS)

security: ## Run bandit security scanner
	bandit -r $(SRC) plugins/ -c pyproject.toml -q

typecheck: ## Run mypy type checker
	mypy $(SRC) plugins/ --ignore-missing-imports

# ── Testing ──────────────────────────────────

test: ## Run pytest
	pytest tests/ -v --tb=short

test-cov: ## Run pytest with coverage report
	pytest tests/ -v --tb=short \
		--cov=cascavel \
		--cov=sarif_exporter \
		--cov-report=term-missing \
		--cov-report=html:htmlcov

# ── Compile Check ────────────────────────────

compile: ## Verify all Python files compile
	@$(PYTHON) -m py_compile cascavel.py && echo "✅ cascavel.py"
	@$(PYTHON) -m py_compile sarif_exporter.py && echo "✅ sarif_exporter.py"
	@$(PYTHON) -m py_compile report_generator.py && echo "✅ report_generator.py"
	@find plugins/ -name "*.py" -exec $(PYTHON) -m py_compile {} \; && echo "✅ plugins/"
	@find tests/ -name "*.py" -exec $(PYTHON) -m py_compile {} \; && echo "✅ tests/"

# ── Profiles ─────────────────────────────────

profiles: ## Validate YAML scan profiles
	@$(PYTHON) -c "import yaml, os; [yaml.safe_load(open(os.path.join('profiles',f))) for f in os.listdir('profiles') if f.endswith('.yaml')]; print('✅ All profiles valid')"

# ── SARIF ─────────────────────────────────────

sarif-validate: ## Validate SARIF exporter output
	@$(PYTHON) -c "\
	import json, tempfile, sys; sys.path.insert(0,'.'); \
	from sarif_exporter import export_sarif; \
	d = tempfile.mkdtemp(); \
	p = export_sarif('test.com','1.2.3.4',[{'plugin':'t','severity':'HIGH','title':'T','findings':[{'x':1}]}],1.0,output_dir=d); \
	s = json.load(open(p)); \
	assert s['version']=='2.1.0'; \
	print('✅ SARIF output valid')"

# ── Docker ───────────────────────────────────

docker: ## Build Docker image
	docker build -t cascavel:3.0.0 .

docker-run: ## Run Docker container (--help)
	docker run --rm cascavel:3.0.0 --help

# ── Combined ─────────────────────────────────

check: lint security compile profiles ## Run lint + security + compile + profiles (CI gate)
	@echo "✅ All checks passed"

all: lint format security test compile profiles sarif-validate ## Run everything

# ── Cleanup ──────────────────────────────────

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ .eggs/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	rm -rf htmlcov/ .coverage coverage.xml test-results.xml
	@echo "🧹 Clean complete"
