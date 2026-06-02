# Bastion — common tasks.
# Windows note: these targets call `python` and `docker compose`; they work in
# Git Bash / WSL / make-for-Windows. The underlying commands are cross-platform.

PYTHON ?= python
SLOS   ?= slos.example.yaml
OUT    ?= out
COMPOSE = docker compose -f deploy/docker-compose.yml

.PHONY: help install test generate validate show run up down demo clean

help:
	@echo "Bastion targets:"
	@echo "  make install    install runtime + test deps"
	@echo "  make test       run the offline test suite"
	@echo "  make generate   generate Prometheus rules + Grafana dashboard -> $(OUT)/"
	@echo "  make validate   validate the security-SLO YAML"
	@echo "  make show       print computed burn-rate thresholds per SLO"
	@echo "  make run        run the exporter locally (metrics + ingest API)"
	@echo "  make up         start the full demo stack (docker compose)"
	@echo "  make demo       up + tail the secgen log so dashboards come alive"
	@echo "  make down       stop the demo stack"
	@echo "  make clean      remove generated artifacts"

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install pytest httpx

test:
	$(PYTHON) -m pytest

generate:
	$(PYTHON) -m bastion.cli generate -f $(SLOS) -o $(OUT)

validate:
	$(PYTHON) -m bastion.cli validate -f $(SLOS)

show:
	$(PYTHON) -m bastion.cli show -f $(SLOS)

run:
	$(PYTHON) -m bastion.exporter --config config.example.yaml

up:
	$(COMPOSE) up --build -d

demo: up
	@echo "Stack is up. Grafana: http://localhost:3000 (admin/admin)"
	$(COMPOSE) logs -f secgen

down:
	$(COMPOSE) down -v

clean:
	rm -rf $(OUT)
