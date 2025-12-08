# --- Makefile ---
include .env

.PHONY: netcheck up down build pull deploy migrate backup superuser create-certs

NETCHECK_CMD = ./scripts/check-network.sh

up:
	$(NETCHECK_CMD)
	@echo "Starting services..."
	@docker compose --env-file .env up -d

down:
	$(NETCHECK_CMD)
	@echo "Stopping services..."
	@docker compose --env-file .env down --remove-orphans

build:
	$(NETCHECK_CMD)
	@echo "Building images..."
	@docker compose --env-file .env build

pull:
	$(NETCHECK_CMD)
	@echo "Pulling images..."
	@docker compose --env-file .env pull

deploy:
	$(NETCHECK_CMD)
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
