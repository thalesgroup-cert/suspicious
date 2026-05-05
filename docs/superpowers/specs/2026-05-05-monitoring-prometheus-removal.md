# Monitoring — Prometheus Stack Removal

**Date:** 2026-05-05
**Branch:** feature/frontweb
**Status:** Applied (commit `6a2941c`)
**Supersedes parts of:** `2026-04-15-architecture-review-design.md` (O3), `2026-04-27-o3-o5-metrics-alerting-design.md`

---

## Why

`django==6.0.4` upgrade landed on the branch. `django-prometheus==2.4.1` is
not compatible with Django 6.x — it pins `django<5.2` in its install
metadata and its middleware imports break under the new request lifecycle.
No upstream release is available at time of writing.

Rather than block the Django bump or fork `django-prometheus`, the in-app
Prometheus path was removed. Observability moves entirely to the
OpenTelemetry stack already wired up (`82becc1`, `49e2e12`, `5f11fde`,
`68d00b0`, `87e956e`).

## What was removed (commit `6a2941c`)

| Artefact | Path | Notes |
|---|---|---|
| `django-prometheus` package | `Suspicious/requirements.txt` | dropped from observability section |
| `django_prometheus` app | `Suspicious/Suspicious/suspicious/settings.py` | removed from `INSTALLED_APPS` |
| `PrometheusBefore/AfterMiddleware` | `Suspicious/Suspicious/suspicious/settings.py` | removed from `MIDDLEWARE` |
| `/metrics` URL include | `Suspicious/Suspicious/suspicious/urls.py` | `django_prometheus.urls` no longer mounted |
| `QUEUE_COLLECTOR` registration | `Suspicious/Suspicious/api/apps.py` | `ApiConfig.ready` reduced to default |
| Custom `api/metrics.py` | `Suspicious/Suspicious/api/metrics.py` | deleted (defined `cases_created_total`, `submission_queue_depth`, etc.) |
| `compose_monitoring.yaml` | `deployment/compose_monitoring.yaml` | deleted (Prometheus + Grafana + mariadb-exporter profile) |
| Prometheus scrape config | `monitoring/prometheus.yml` | deleted |
| Grafana provisioning | `monitoring/graphana/provisioning/{dashboards,datasources}` | deleted |
| Make targets | `deployment/Makefile` | `monitor-up`, `monitor-down`, `monitor-logs` removed; help text updated |

A stale `case_handler/signals.py` receiver that imported the deleted
`api.metrics` was neutralised in commit `01c84c6`.

## What stays — current observability stack

| Layer | Status | Path |
|---|---|---|
| Structured JSON logs | Live | `d3a6a4d` JsonFormatter wiring |
| `trace_id` injection in log records | Live | `49e2e12` `TraceIdFilter` |
| OTel SDK init (Django + requests instrumentation) | Live | `1c67a45`, `82becc1` |
| Named spans on cron + scoring entry points | Live | `5f11fde` |
| Trace backend (Tempo) | Live | `ce34821` `compose_monitoring.yaml` predecessor — Tempo runs as part of base stack |
| Settings keys for OTel toggles | Live | `87e956e` `observability.opentelemetry.*` documented |

## Items deferred / now out of scope

The architecture review's **O3** (business Prometheus metrics) and **O5**
(AlertManager rules) are no longer the planned route.

If we want application metrics again, the supported path is:

1. Use OTel **metrics** API (already in the SDK, currently disabled) and
   export OTLP to a metrics backend (Mimir, Prometheus remote-write
   compatible, or otel-collector → Prometheus).
2. Re-add a `compose_metrics.yaml` profile pointed at the OTel collector,
   not at `django-prometheus`.
3. Define alert rules in the metrics backend, not in the removed
   AlertManager file.

Do **not** add `django-prometheus` back unless an upstream Django-6
compatible release ships.

## Migration / deploy notes

- No DB migration.
- No `/metrics` endpoint to scrape — anything still pointing at
  `https://<host>/metrics` will 404. Update external scrape configs.
- `make monitor-up` etc. no longer exist; remove from any runbook.
- Tempo / OTel collector remain reachable via their own service
  definitions in the live compose files.
