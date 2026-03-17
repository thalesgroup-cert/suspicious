# --- Makefile ---
.PHONY: help netcheck up down build pull deploy migrate backup superuser create-certs init

help:
	@echo "Available targets:"
	@echo "  init         - Initialize the project"
	@echo "  up           - Start services"
	@echo "  down         - Stop services"
	@echo "  build        - Build images"
	@echo "  pull         - Pull images"
	@echo "  deploy       - Deploy application"
	@echo "  migrate      - Run migrations"
	@echo "  backup       - Backup database"
	@echo "  superuser    - Create superuser"
	@echo "  create-certs - Generate certificates"

init:
	@echo "Initializing project..."
	@./scripts/init.sh
	@echo "Initialization complete."

include .env

NETCHECK_CMD = ./scripts/check-network.sh
REPLACE_TLS_CMD = ./scripts/replace-tls.sh

up:
	$(NETCHECK_CMD)
	$(REPLACE_TLS_CMD)
	@echo "Starting services..."
	@docker compose --env-file .env up -d

down:
	@echo "Stopping services..."
	@docker compose --env-file .env down --remove-orphans

build:
	@echo "Building images..."
	@docker compose --env-file .env build

pull:
	@echo "Pulling images..."
	@docker compose --env-file .env pull

deploy:
	$(NETCHECK_CMD)
	$(REPLACE_TLS_CMD)
	./scripts/wait-empty.sh "/tmp/emailAnalysis"
	@echo "Deploying..."
	@./scripts/deploy.sh

migrate:
	@echo "Running migrations..."
	@./scripts/migrate.sh

backup:
	@echo "Backing up database..."
	@./scripts/backup-db.sh

superuser:
	@echo "Creating superuser..."
	@./scripts/create-superuser.sh

create-certs:
	@echo "Generating certificates..."
	@./scripts/openssl-certificates-generator.sh
