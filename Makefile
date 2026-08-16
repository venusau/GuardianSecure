# GuardianSecure — developer & ops commands
# Usage: make <target>

PYTHON ?= ./myenv/bin/python
PIP    ?= ./myenv/bin/pip
COMPOSE ?= docker compose

# Default DB targeted by `make migrate` (the Docker Postgres, port-mapped to
# localhost). Override if you need to migrate a different database, e.g.:
#   make migrate MIGRATE_DB=postgresql://user:pass@host:5432/dbname
MIGRATE_DB ?= postgresql://guardian:guardian@localhost:5432/guardian

.PHONY: help install dev-install lint format format-check test-scan migrate init-db \
        run-gateway run-worker run-notifier shell \
        docker-up docker-down docker-build docker-logs \
        temporal-start kafka-topics clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies into the virtualenv
	$(PIP) install -r requirements.txt

dev-install:  ## Install deps + dev tools
	$(PIP) install -r requirements.txt
	$(PIP) install pytest ruff black

lint:  ## Lint with ruff
	$(PYTHON) -m ruff check project scanner libs temporal services

format:  ## Auto-format with black + ruff --fix
	$(PYTHON) -m ruff check --fix project scanner libs temporal services
	$(PYTHON) -m black project scanner libs temporal services tests

format-check:  ## Verify formatting (CI friendly, no writes)
	$(PYTHON) -m ruff check project scanner libs temporal services
	$(PYTHON) -m black --check project scanner libs temporal services

test-scan:  ## Run a quick self-test of the in-house scanner
	$(PYTHON) -m pytest tests/test_scanner.py -q

migrate:  ## Apply database migrations (Alembic) — targets local Docker Postgres
	DATABASE_URI=$(MIGRATE_DB) $(PYTHON) -m alembic upgrade head

init-db: migrate  ## Alias for applying migrations

run-gateway:  ## Run the Flask API gateway (dev)
	$(PYTHON) app.py

run-worker:  ## Run the Temporal scan worker
	$(PYTHON) temporal/worker.py

run-notifier:  ## Run the Kafka->Email notification worker
	$(PYTHON) services/notification/consumer.py

shell:  ## Open a Flask shell with app context
	FLASK_APP=app.py $(PYTHON) -m flask shell

docker-build:  ## Build all service images
	$(COMPOSE) build

docker-up:  ## Start the full stack (gateway, postgres, redis, kafka, temporal, workers)
	$(COMPOSE) up -d

docker-down:  ## Stop the full stack
	$(COMPOSE) down

docker-logs:  ## Tail logs from all services
	$(COMPOSE) logs -f

temporal-start:  ## Start a local Temporal dev server (requires temporal CLI)
	temporal server start-dev --db-filename /tmp/temporal.db

kafka-topics:  ## Create the Kafka topics used by the pipeline
	$(PYTHON) -c "from libs.kafka_client import kafka_gateway; \
	  print('Kafka enabled:', kafka_gateway.enabled)"

clean:  ## Remove pycache and build artifacts
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
	rm -rf build dist *.egg-info
