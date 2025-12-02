include .env

.PHONY: netcheck up down build pull deploy migrate backup superuser create-certs

check-network:
	./scripts/check-network.sh

up:
	docker compose up -d

down:
	docker compose down --remove-orphans

build:
	docker compose build

pull:
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