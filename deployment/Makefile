# Makefile — Suspicious platform
#
# Usage:
#   make help             → list all targets
#   make install          → first-time interactive setup (recommended)
#   make init             → non-interactive setup (network, certs, env check)
#   make deploy           → zero-downtime rolling deploy
#   make upgrade          → same as deploy (alias for clarity)
#   make up               → start all services
#   make down             → stop all containers
#   make monitor-up       → start Prometheus + Grafana (optional)
#   make check-updates    → compare running images vs registry

-include .env

COMPOSE         := docker compose --env-file .env
SCRIPTS         := ./scripts

BACKUP_DIR      := ./backups
TIMESTAMP       := $(shell date +%Y%m%d_%H%M%S)
BACKUP_FILE     := $(BACKUP_DIR)/$(MYSQL_DATABASE)_$(TIMESTAMP).sql.gz

BOLD  := $(shell tput bold 2>/dev/null || true)
GREEN := $(shell tput setaf 2 2>/dev/null || true)
RESET := $(shell tput sgr0 2>/dev/null || true)
OK    := @echo "$(GREEN)$(BOLD)✓$(RESET)"

define require_script
	@test -x $(1) || (echo "Missing or non-executable: $(1)" && exit 1)
endef

.PHONY: help install init up down build pull deploy upgrade restart \
        migrate collectstatic createsuperuser \
        backup-db restore-db \
        logs status shell db-shell \
        create-certs network clean prune \
        check-secrets check-updates

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help:
	@echo ""
	@echo "$(BOLD)Suspicious — available targets$(RESET)"
	@echo ""
	@echo "$(BOLD)Getting started$(RESET)"
	@echo "  install          Interactive setup wizard (recommended for new installs)"
	@echo "  init             Non-interactive setup (network, certs, config files)"
	@echo ""
	@echo "$(BOLD)Deployment$(RESET)"
	@echo "  deploy           Zero-downtime rolling deploy (pull → migrate → restart)"
	@echo "  upgrade          Alias for deploy"
	@echo "  up               Start all services (no pull, no migration)"
	@echo "  down             Stop and remove containers (data preserved)"
	@echo "  restart          Restart all running services"
	@echo "  build            Build local images"
	@echo "  pull             Pull remote images without restarting"
	@echo ""
	@echo "$(BOLD)Django$(RESET)"
	@echo "  migrate          Run database migrations"
	@echo "  collectstatic    Collect static files"
	@echo "  createsuperuser  Create a Django superuser interactively"
	@echo ""
	@echo "$(BOLD)Database$(RESET)"
	@echo "  backup-db        Dump MariaDB to ./backups/ (gzipped, timestamped)"
	@echo "  restore-db f=<file>   Restore from a .sql.gz dump"
	@echo ""
	@echo "$(BOLD)Diagnostics$(RESET)"
	@echo "  check-secrets    Verify no placeholder secrets remain in .env"
	@echo "  check-updates    Compare running image digests vs registry"
	@echo "  logs [s=<svc>]   Follow logs — all or one service"
	@echo "  status           Show container health and status"
	@echo "  shell            Open bash in the web container"
	@echo "  db-shell         Open a MariaDB shell"
	@echo ""
	@echo "$(BOLD)Cleanup$(RESET)"
	@echo "  clean            Remove stopped containers"
	@echo "  prune            Remove ALL unused Docker resources (irreversible)"
	@echo ""

# ---------------------------------------------------------------------------
# Getting started
# ---------------------------------------------------------------------------

## Interactive installer — guides through all config, then starts the stack
install:
	@python3 install.py

## Non-interactive setup (called automatically by install.py)
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
	@$(SCRIPTS)/openssl-certificates-generator.sh
	$(OK) "Certificates generated in $(CA_PATH)."

# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

## Zero-downtime rolling deploy (recommended)
deploy: check-secrets
	$(call require_script,$(SCRIPTS)/deploy.sh)
	@$(SCRIPTS)/deploy.sh
	$(OK) "Deploy complete."

## Alias — communicates intent more clearly in upgrade contexts
upgrade: deploy

## Start all services (no pull or migration)
up: check-secrets
	$(call require_script,$(SCRIPTS)/check-network.sh)
	$(call require_script,$(SCRIPTS)/replace-tls.sh)
	@$(SCRIPTS)/check-network.sh
	@$(SCRIPTS)/replace-tls.sh
	@echo "Starting services…"
	@$(COMPOSE) up -d --remove-orphans
	$(OK) "Services started."

## Stop all containers (volumes and data preserved)
down:
	@$(COMPOSE) down --remove-orphans
	$(OK) "Services stopped."

## Restart all services
restart:
	@$(COMPOSE) restart
	$(OK) "Services restarted."

## Build local images
build:
	@$(COMPOSE) build
	$(OK) "Build complete."

## Pull remote images without restarting
pull:
	@$(COMPOSE) pull
	$(OK) "Images pulled."

# ---------------------------------------------------------------------------
# Django management
# ---------------------------------------------------------------------------

migrate:
	$(call require_script,$(SCRIPTS)/migrate.sh)
	@$(SCRIPTS)/migrate.sh
	$(OK) "Migrations applied."

collectstatic:
	@$(COMPOSE) exec suspicious \
		python3 manage.py collectstatic --no-input --clear
	$(OK) "Static files collected."

createsuperuser:
	$(call require_script,$(SCRIPTS)/create-superuser.sh)
	@$(SCRIPTS)/create-superuser.sh

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

backup-db:
	$(call require_script,$(SCRIPTS)/backup-db.sh)
	@mkdir -p $(BACKUP_DIR)
	@$(SCRIPTS)/backup-db.sh $(BACKUP_FILE)
	$(OK) "Backup saved: $(BACKUP_FILE)"

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
# Read replica (R6)
# ---------------------------------------------------------------------------

## Bootstrap the read replica from primary (one-time, run after `make up`).
## Requires REPL_PASSWORD in .env. Wipes any existing replica volume.
db-replica-init:
	@$(SCRIPTS)/init-replica.sh
	$(OK) "Replica initialized. Add database.replica block to settings.json to route reads."

## Start the replica (after init)
replica-up:
	@$(COMPOSE) --profile replica up -d db_suspicious_replica
	$(OK) "Replica started."

## Stop the replica
replica-down:
	@$(COMPOSE) --profile replica stop db_suspicious_replica
	$(OK) "Replica stopped."

## Show replication status (Slave_IO_Running, Seconds_Behind_Master, etc.)
replica-status:
	@$(COMPOSE) exec db_suspicious_replica mariadb \
		--user=root --password=$$(grep ^MYSQL_ROOT_PASSWORD .env | cut -d= -f2) \
		-e 'SHOW SLAVE STATUS\G'


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

## Verify no placeholder secrets in .env
check-secrets:
	$(call require_script,$(SCRIPTS)/check-secrets.sh)
	@$(SCRIPTS)/check-secrets.sh .env

## Compare running image digests against registry
check-updates:
	$(call require_script,$(SCRIPTS)/check-updates.sh)
	@$(SCRIPTS)/check-updates.sh

## Follow logs — all services or one: make logs s=suspicious
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

clean:
	@$(COMPOSE) rm -f

prune:
	@echo "$(BOLD)⚠  Removing all unused Docker images and dangling volumes.$(RESET)"
	@echo "   Press Ctrl-C within 5 seconds to abort."
	@sleep 5
	@docker system prune -f
	@docker volume prune -f
	$(OK) "Prune complete."