# R1 + P1 — Redis + Celery Design
**Date:** 2026-04-17
**Scope:** Replace `django-crontab` with Celery + Redis (R1); add Redis cache for sessions and dashboard (P1)
**Reviewer:** Claude Code (claude-sonnet-4-6) + TheoBhang

---

## Context

Suspicious currently runs all periodic work via `django-crontab` in a `suspicious_cron` container (`service cron start`). A cron daemon crash stalls the entire processing pipeline silently. Sessions hit MariaDB on every authenticated request. Dashboard summary views read from pre-materialized KPI tables but still pay a DB round-trip per request.

This design replaces the cron container with Celery (worker + Beat), adds two Redis containers (broker and cache), switches sessions to the Redis cache backend, and caches dashboard summary responses with a 2-minute TTL.

---

## Architecture

### New Containers

| Container | Role | Image | Internal Port | Persistence |
|---|---|---|---|---|
| `redis_broker` | Celery task broker | `redis:7-alpine` | 6379 | none |
| `redis_cache` | Django cache (sessions + dashboard) | `redis:7-alpine` | 6380 | none |
| `suspicious_celery` | Celery worker + Beat (combined) | same as `suspicious` | — | — |

`suspicious_cron` is removed.

Both Redis containers are ephemeral (no named volumes). Cache data is reconstructable; broker data loss on restart means in-flight tasks are retried by Beat on next tick.

### Container Dependencies

```
redis_broker   ─┐
suspicious     ─┴─▶  suspicious_celery
```

`suspicious_celery` depends on `redis_broker: service_started` and `suspicious: service_healthy`.

---

## Section 1 — Infrastructure

### `deployment/compose_databases.yaml`

Two Redis service definitions added:

```yaml
redis_broker:
  image: redis:${REDIS_BROKER_VERSION:-7-alpine}
  container_name: redis_broker
  restart: always
  networks:
    - suspicious_network

redis_cache:
  image: redis:${REDIS_CACHE_VERSION:-7-alpine}
  container_name: redis_cache
  restart: always
  command: redis-server --port 6380
  networks:
    - suspicious_network
```

### `deployment/docker-compose.yml`

- Add `redis_broker` and `redis_cache` service stanzas (extending `compose_databases.yaml`).
- Remove `suspicious_cron` service stanza.
- Add `suspicious_celery` service (extending `compose_apps.yaml`).

### `deployment/compose_apps.yaml`

Remove `suspicious_cron` service definition.

Add `suspicious_celery`:

```yaml
suspicious_celery:
  init: true
  restart: always
  command: celery -A suspicious worker --beat --loglevel=info
  volumes:
    - "${CA_PATH}/certfile.pem:/etc/private/certfile.pem:ro"
    - "${CA_PATH}/keyfile.pem:/etc/private/keyfile.pem:ro"
    - "${CA_PATH}/rootcafile.pem:/etc/private/rootcafile.pem:ro"
    - "${SUSPICIOUS_PATH}/logs:/app/log"
    - "${SUSPICIOUS_PATH}/settings.json:/app/settings.json:ro"
  env_file:
    - ".env"
  environment:
    no_proxy: "${NO_PROXY:-},cortex,db_suspicious,rustfs,chromadb,redis_broker,redis_cache"
  healthcheck:
    test: ["CMD-SHELL", "celery -A suspicious inspect ping -d celery@$$HOSTNAME || exit 1"]
    interval: 60s
    timeout: 10s
    retries: 3
    start_period: 30s
  networks:
    - suspicious_network
```

### `deployment/.env`

```
REDIS_BROKER_VERSION=7-alpine
REDIS_CACHE_VERSION=7-alpine
```

---

## Section 2 — Django & Celery Config

### New file: `Suspicious/Suspicious/suspicious/celery.py`

```python
import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suspicious.settings")

app = Celery("suspicious")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
```

### `Suspicious/Suspicious/suspicious/__init__.py`

```python
from .celery import app as celery_app

__all__ = ("celery_app",)
```

### `settings.py` additions

Redis connection strings are read from `settings.json` under a new `"redis"` key:

```python
_redis_conf = _settings.get("redis", {})
_broker_host = _redis_conf.get("broker_host", "redis_broker")
_cache_host  = _redis_conf.get("cache_host",  "redis_cache")

# Celery
CELERY_BROKER_URL         = f"redis://{_broker_host}:6379/0"
CELERY_RESULT_BACKEND     = "django-db"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_SERIALIZER    = "json"
CELERY_ACCEPT_CONTENT     = ["json"]

# Cache
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"redis://{_cache_host}:6380/0",
    }
}

# Sessions → Redis cache
SESSION_ENGINE               = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS          = "default"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY      = True

# Beat schedule (replaces CRONJOBS)
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "fetch-emails": {
        "task": "tasp.tasks.fetch_emails",
        "schedule": 60.0,
    },
    "sync-cortex": {
        "task": "tasp.tasks.sync_cortex",
        "schedule": 60.0,
    },
    "update-ongoing-cases": {
        "task": "tasp.tasks.update_ongoing_cases",
        "schedule": 60.0,
    },
    "check-challengeable": {
        "task": "tasp.tasks.check_challengeable",
        "schedule": crontab(hour=0, minute=0),
    },
    "sync-monthly-kpi": {
        "task": "tasp.tasks.sync_monthly_kpi",
        "schedule": 300.0,
    },
    "sync-user-profiles": {
        "task": "tasp.tasks.sync_user_profiles",
        "schedule": 600.0,
    },
    "delete-old-reports": {
        "task": "tasp.tasks.delete_old_reports",
        "schedule": crontab(day_of_month=1, hour=0, minute=0),
    },
    "remove-old-emails": {
        "task": "tasp.tasks.remove_old_emails",
        "schedule": crontab(hour=0, minute=0),
    },
    "watcher-sync": {
        "task": "tasp.tasks.watcher_sync",
        "schedule": 300.0,
    },
}
```

### `INSTALLED_APPS` changes

```python
# Remove:
"django_crontab",

# Add:
"django_celery_results",
```

Remove `CRONJOBS` and `CRONTAB_LOCK_JOBS` settings entirely.

### `settings.json` schema

Add under `"integrations"` (or top-level):

```json
"redis": {
  "broker_host": "redis_broker",
  "cache_host": "redis_cache"
}
```

---

## Section 3 — Task Wrappers

### New file: `Suspicious/Suspicious/tasp/tasks.py`

All existing `tasp/cron/*.py` functions remain unchanged. This file wraps them as Celery tasks.

Imports are lazy (inside task body) to avoid module-level `open(CONFIG_PATH)` calls in `suspicious.py` and `watcher.py` executing at worker startup before the filesystem is ready.

Retry policy: 3 attempts, exponential backoff (60s → 120s → 240s). `acks_late=True` prevents silent task loss on worker crash. Backoff implemented via `countdown` in `self.retry()`.

```python
from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=3, acks_late=True)


@shared_task(bind=True, **_RETRY)
def fetch_emails(self):
    from tasp.cron.fetch_emails import fetch_and_process_emails
    try:
        fetch_and_process_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_cortex(self):
    from tasp.cron.sync_cortex import sync_cortex_analyzers
    try:
        sync_cortex_analyzers()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def update_ongoing_cases(self):
    from tasp.cron.user_and_cases import update_ongoing_case_jobs
    try:
        update_ongoing_case_jobs()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def check_challengeable(self):
    from tasp.cron.suspicious import check_challengeable as _check
    try:
        _check()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_monthly_kpi(self):
    from tasp.cron.kpi import sync_monthly_kpi as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_user_profiles(self):
    from tasp.cron.user_and_cases import sync_user_profiles as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def delete_old_reports(self):
    from tasp.cron.cleanup import delete_old_analyzer_reports
    try:
        delete_old_analyzer_reports()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def remove_old_emails(self):
    from tasp.cron.suspicious import remove_old_suspicious_emails
    try:
        remove_old_suspicious_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def watcher_sync(self):
    from tasp.cron.watcher import run_watcher_sync
    try:
        run_watcher_sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)
```

---

## Section 4 — Failed Task Admin

`django-celery-results` writes every task result (status, traceback, args, kwargs) to `django_celery_results_taskresult`. No custom model needed.

### New file: `Suspicious/Suspicious/tasp/admin.py`

Extends the default `TaskResultAdmin` with a requeue action. Only `FAILURE` rows are acted on; other statuses are silently skipped.

```python
from django.contrib import admin
from django_celery_results.models import TaskResult
from django_celery_results.admin import TaskResultAdmin as BaseAdmin
import json
from celery import current_app


@admin.register(TaskResult)
class TaskResultAdmin(BaseAdmin):
    actions = ["requeue_failed"]

    @admin.action(description="Requeue selected failed tasks")
    def requeue_failed(self, request, queryset):
        requeued = 0
        for result in queryset.filter(status="FAILURE"):
            try:
                args = json.loads(result.task_args or "[]")
                kwargs = json.loads(result.task_kwargs or "{}")
                current_app.send_task(result.task_name, args=args, kwargs=kwargs)
                requeued += 1
            except Exception:
                pass
        self.message_user(request, f"Requeued {requeued} task(s).")
```

Failed tasks visible at: `/admin/django_celery_results/taskresult/?status=FAILURE`

---

## Section 5 — Dashboard Cache

Cache key: `dashboard:summary:{year}:{month}:{scope}` — scope prevents CISO and non-CISO users sharing a cache entry with different data.

TTL: **120 seconds** (2 minutes). No explicit invalidation — KPI syncs every 5 minutes; 2-minute stale window is acceptable.

### `Suspicious/Suspicious/api/views/dashboard.py` — `DashboardSummaryView.get()`

```python
from django.core.cache import cache

DASHBOARD_CACHE_TTL = 120

def get(self, request):
    query = DashboardSummaryQuerySerializer(data=request.query_params)
    query.is_valid(raise_exception=True)

    month = query.validated_data["month"]
    year = query.validated_data["year"]
    requested_scope = query.validated_data.get("scope", "ALL")
    scope = self._resolve_scope(requested_scope=requested_scope)

    cache_key = f"dashboard:summary:{year}:{month}:{scope}"
    payload = cache.get(cache_key)
    if payload is None:
        payload = self._build_summary_payload(month=month, year=year, scope=scope)
        cache.set(cache_key, payload, DASHBOARD_CACHE_TTL)

    return Response(DashboardSummaryResponseSerializer(instance=payload).data)
```

Same pattern applied to `MonthlyCasesSummaryAggregateView` and `UserCasesMonthlyStatsAggregateView` with keys:
- `dashboard:monthly-cases:{year}:{month}`
- `dashboard:user-stats:{year}:{month}`

---

## Section 6 — Dependencies

### `Suspicious/requirements.txt`

```diff
-django_crontab
+celery[redis]~=5.3
+django-celery-results~=2.5
```

`redis` Python client is pulled transitively by `celery[redis]`. Django's built-in `RedisCache` backend (`django.core.cache.backends.redis.RedisCache`) requires no extra package (available since Django 4.0).

---

## Migration Steps

1. `pip install celery[redis] django-celery-results`
2. `python manage.py migrate django_celery_results`
3. `python manage.py migrate` (session table no longer needed — sessions now in Redis)
4. Deploy new containers: `docker compose up -d redis_broker redis_cache suspicious_celery`
5. Take down old cron: `docker compose stop suspicious_cron && docker compose rm -f suspicious_cron`

---

## What Does NOT Change

- All `tasp/cron/*.py` function signatures — untouched
- `tasp/cron/models.py` and `tasp/cron/utils.py` — untouched
- Dashboard view logic (`_build_summary_payload`, `_get_*_aggregate`) — untouched
- All other Django apps — untouched

---

## Decision Log

| Decision | Choice | Reason |
|---|---|---|
| Task structure | Thin wrappers in `tasp/tasks.py` | Minimal disruption to cron logic |
| Redis topology | Two containers (broker + cache) | Broker and cache eviction policies must not interfere |
| DLQ | `django-celery-results` + admin requeue action | No custom model needed; admin UX for free |
| Container | Combined worker+beat (`suspicious_celery`) | Single-node deploy; simplest ops |
| Beat schedule | Hardcoded in `settings.py` | Keeps intervals version-controlled |
| Session backend | Redis cache | Eliminates per-request DB session lookup |
| Dashboard TTL | 2 minutes, no explicit invalidation | YAGNI; TTL covers acceptable stale window |
