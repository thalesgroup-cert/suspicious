include .env

.PHONY: netcheck up down build pull deploy migrate backup superuser create-certs

netcheck:
	./scripts/check-network.sh

up:
	./scripts/check-network.sh
	docker compose up -d

down:
	./scripts/check-network.sh
	docker compose down --remove-orphans

build:
	./scripts/check-network.sh
	docker compose build

pull:
	./scripts/check-network.sh
	docker compose pull

deploy:
	./scripts/check-network.sh
	./scripts/wait-empty.sh "/tmp/emailAnalysis"
	./scripts/deploy.sh

migrate:
	./scripts/migrate.sh

backup:
	./scripts/backup-db.sh

superuser:
	./scripts/create-superuser.sh

create-certs:
	./scripts/openssl-certificates-generator.sh