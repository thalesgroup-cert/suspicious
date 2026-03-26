# Makefile — Suspicious platform
#
# Delegates complex operations to ./scripts/ (your pattern, preserved).
# Inline logic is used only where a single docker compose call suffices.
#
# Usage:
#   make help             → list all targets with descriptions
#   make init             → first-time setup (network, certs, .env check)
#   make deploy           → full production deploy (pull → migrate → restart)
#   make up               → start all services (no image pull)
#   make down             → stop all containers (data preserved)
#
# Requires: docker (compose v2), make, bash

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

-include .env

COMPOSE         := docker compose --env-file .env
DC_FILE         := docker-compose.yml

SCRIPTS         := ./scripts
NETCHECK        := $(SCRIPTS)/check-network.sh
REPLACE_TLS     := $(SCRIPTS)/replace-tls.sh
WAIT_EMPTY      := $(SCRIPTS)/wait-empty.sh

BACKUP_DIR      := ./backups
TIMESTAMP       := $(shell date +%Y%m%d_%H%M%S)
BACKUP_FILE     := $(BACKUP_DIR)/$(MYSQL_DATABASE)_$(TIMESTAMP).sql.gz

# Colour helpers (no-op if terminal doesn't support them)
BOLD  := $(shell tput bold 2>/dev/null || true)
GREEN := $(shell tput setaf 2 2>/dev/null || true)
RESET := $(shell tput sgr0 2>/dev/null || true)
OK    := @echo "$(GREEN)$(BOLD)✓$(RESET)"

# Guard: fail immediately if a required script is missing
define require_script
	@test -x $(1) || (echo "Missing or non-executable: $(1)" && exit 1)
endef

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: help init up down build pull deploy restart \
        migrate collectstatic createsuperuser \
        backup-db restore-db \
        logs status shell db-shell \
        create-certs network clean prune

# ---------------------------------------------------------------------------
# Help  (auto-generated from ## comments)
# ---------------------------------------------------------------------------

help:
	@echo ""
	@echo "$(BOLD)Suspicious — available targets$(RESET)"
	@echo ""
	@echo "$(BOLD)Setup$(RESET)"
	@echo "  init             First-time project initialization (network, certs, env check)"
	@echo "  network          Create the Docker bridge network"
	@echo "  create-certs     Generate TLS certificates via OpenSSL"
	@echo ""
	@echo "$(BOLD)Deployment$(RESET)"
	@echo "  deploy           Full deploy: network check → TLS → pull → migrate → restart"
	@echo "  up               Start all services (no pull, no migration)"
	@echo "  down             Stop and remove containers (data preserved)"
	@echo "  restart          Restart all running services"
	@echo "  build            Build local images (suspicious_ui, feeder)"
	@echo "  pull             Pull remote images without restarting"
	@echo ""
	@echo "$(BOLD)Django$(RESET)"
	@echo "  migrate          Run database migrations"
	@echo "  collectstatic    Collect static files"
	@echo "  createsuperuser  Create a Django superuser interactively"
	@echo ""
	@echo "$(BOLD)Database$(RESET)"
	@echo "  backup-db        Dump MariaDB to ./backups/ (gzipped, timestamped)"
	@echo "  restore-db f=<file>   Restore from a .sql.gz dump (5-second abort window)"
	@echo ""
	@echo "$(BOLD)Diagnostics$(RESET)"
	@echo "  logs [s=<svc>]   Follow logs — all services or one (e.g. s=suspicious)"
	@echo "  status           Show container health and status"
	@echo "  shell            Open a bash shell in the web container"
	@echo "  db-shell         Open a MariaDB shell"
	@echo ""
	@echo "$(BOLD)Cleanup$(RESET)"
	@echo "  clean            Remove stopped containers"
	@echo "  prune            Remove ALL unused Docker resources (irreversible)"
	@echo ""

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

## First-time project initialization
init:
	$(call require_script,$(SCRIPTS)/init.sh)
	@echo "$(BOLD)Initializing project…$(RESET)"
	@$(SCRIPTS)/init.sh
	$(OK) "Initialization complete."

## Create the Docker bridge network (idempotent)
network:
	@docker network create \
		--driver bridge \
		--subnet $(NETWORK_SUBNET) \
		--gateway $(NETWORK_GATEWAY) \
		--ip-range $(NETWORK_IP_RANGE) \
		$(NETWORK_NAME) 2>/dev/null \
	&& echo "$(GREEN)$(BOLD)✓$(RESET) Network $(NETWORK_NAME) created." \
	|| echo "Network $(NETWORK_NAME) already exists — skipping."

## Generate TLS certificates
create-certs:
	$(call require_script,$(SCRIPTS)/openssl-certificates-generator.sh)
	@echo "Generating certificates…"
	@$(SCRIPTS)/openssl-certificates-generator.sh
	$(OK) "Certificates generated in $(CA_PATH)."

# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

## Full production deploy
deploy:
	$(call require_script,$(NETCHECK))
	$(call require_script,$(REPLACE_TLS))
	$(call require_script,$(WAIT_EMPTY))
	@echo "$(BOLD)Running pre-deploy checks…$(RESET)"
	@$(NETCHECK)
	@$(REPLACE_TLS)
	@$(WAIT_EMPTY) "/tmp/emailAnalysis"
	@echo "$(BOLD)Deploying…$(RESET)"
	@$(SCRIPTS)/deploy.sh
	$(OK) "Deploy complete."

## Start all services (no pull or migration)
up:
	$(call require_script,$(NETCHECK))
	$(call require_script,$(REPLACE_TLS))
	@$(NETCHECK)
	@$(REPLACE_TLS)
	@echo "Starting services…"
	@$(COMPOSE) up -d --remove-orphans
	$(OK) "Services started."

## Stop all containers (volumes and data preserved)
down:
	@echo "Stopping services…"
	@$(COMPOSE) down --remove-orphans
	$(OK) "Services stopped."

## Restart all services
restart:
	@$(COMPOSE) restart
	$(OK) "Services restarted."

## Build local images
build:
	@echo "Building images…"
	@$(COMPOSE) build
	$(OK) "Build complete."

## Pull remote images without restarting
pull:
	@echo "Pulling images…"
	@$(COMPOSE) pull
	$(OK) "Images pulled."

# ---------------------------------------------------------------------------
# Django management
# ---------------------------------------------------------------------------

## Run database migrations
migrate:
	$(call require_script,$(SCRIPTS)/migrate.sh)
	@echo "Running migrations…"
	@$(SCRIPTS)/migrate.sh
	$(OK) "Migrations applied."

## Collect static files
collectstatic:
	@$(COMPOSE) exec suspicious \
		python3 manage.py collectstatic --no-input --clear
	$(OK) "Static files collected."

## Create a Django superuser interactively
createsuperuser:
	$(call require_script,$(SCRIPTS)/create-superuser.sh)
	@$(SCRIPTS)/create-superuser.sh

# ---------------------------------------------------------------------------
# Database backup / restore
# ---------------------------------------------------------------------------

## Dump MariaDB to ./backups/ (gzipped, timestamped)
backup-db:
	$(call require_script,$(SCRIPTS)/backup-db.sh)
	@mkdir -p $(BACKUP_DIR)
	@$(SCRIPTS)/backup-db.sh $(BACKUP_FILE)
	$(OK) "Backup saved: $(BACKUP_FILE)"

## Restore from a dump: make restore-db f=./backups/dump.sql.gz
restore-db:
	@test -n "$(f)" || (echo "Usage: make restore-db f=<dump.sql.gz>" && exit 1)
	@test -f "$(f)" || (echo "File not found: $(f)" && exit 1)
	@echo "$(BOLD)⚠  Restoring $(f) → $(MYSQL_DATABASE). Press Ctrl-C to abort.$(RESET)"
	@sleep 5
	@gunzip -c $(f) | $(COMPOSE) exec -T db_suspicious \
		mariadb \
		  --user=$(MYSQL_USER) \
		  --password=$(MYSQL_PASSWORD) \
		  $(MYSQL_DATABASE)
	$(OK) "Restore complete."

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

## Follow logs — all services, or one: make logs s=suspicious
logs:
	@$(COMPOSE) logs -f --tail=100 $(s)

## Show container health and status
status:
	@$(COMPOSE) ps -a

## Open a bash shell in the web container
shell:
	@$(COMPOSE) exec suspicious /bin/bash

## Open a MariaDB interactive shell
db-shell:
	@$(COMPOSE) exec db_suspicious \
		mariadb \
		  --user=$(MYSQL_USER) \
		  --password=$(MYSQL_PASSWORD) \
		  $(MYSQL_DATABASE)

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

## Remove stopped containers
clean:
	@$(COMPOSE) rm -f

## Remove ALL unused Docker resources — irreversible
prune:
	@echo "$(BOLD)⚠  This removes all unused Docker images and dangling volumes.$(RESET)"
	@echo "   Press Ctrl-C within 5 seconds to abort."
	@sleep 5
	@docker system prune -f
	@docker volume prune -f
	$(OK) "Prune complete."