# Deployment / Infra

Suspicious is deployed with Docker Compose from `deployment/`. All operational
tasks run through the Makefile.

## Common tasks

```bash
make init             # First-time setup: network, TLS certs, config dirs
make up               # Start all services
make build            # Rebuild Docker images
make deploy           # Zero-downtime rolling update (pull → migrate → restart)
make migrate          # Run Django DB migrations
make createsuperuser  # Create a Django admin user
make logs [s=<svc>]   # Follow logs
make status           # Show container health
make backup-db        # Backup MariaDB
make monitor-up       # Enable Tempo + Grafana
```

The full installation walkthrough is in
[Getting Started → Installation](../getting-started/installation.md); operational
runbooks are under [Operations](../operations/deploy.md).
