# Deploy & Rollback

Updates are applied with a zero-downtime rolling update from `deployment/`:

```bash
make deploy   # pull new images → run migrations → restart services in order
```

Individual steps are also available: `make migrate`, `make collectstatic`,
`make build`. Check health afterwards with `make status` and tail logs with
`make logs s=<service>`.

To roll back, redeploy the previous image tags (set in `deployment/.env`) and
run `make deploy` again.
