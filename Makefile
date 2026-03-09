# ML Security RBAC Platform - Makefile
# Author: Gabriel Demetrios Lafis

.PHONY: help install dev test lint format run demo docker-build docker-up docker-down clean

PYTHON  ?= python
PIP     ?= pip
VENV    ?= .venv

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

dev: ## Install all dependencies (including dev tools)
	$(PIP) install -r requirements.txt

test: ## Run the test suite
	$(PYTHON) -m pytest tests/ -v --tb=short

lint: ## Run linter (ruff)
	$(PYTHON) -m ruff check src/ tests/ main.py

format: ## Auto-format code with ruff
	$(PYTHON) -m ruff format src/ tests/ main.py

typecheck: ## Run mypy type checking
	$(PYTHON) -m mypy src/ --ignore-missing-imports

run: ## Start the API server (development)
	$(PYTHON) -m uvicorn src.api.server:app --reload --host 0.0.0.0 --port 8000

demo: ## Run the CLI demo
	$(PYTHON) main.py

docker-build: ## Build Docker image
	docker compose -f docker/docker-compose.yml build

docker-up: ## Start services via Docker Compose
	docker compose -f docker/docker-compose.yml up -d

docker-down: ## Stop Docker Compose services
	docker compose -f docker/docker-compose.yml down

clean: ## Remove generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf data/ logs/ htmlcov/ .coverage dist/ build/ *.egg-info
