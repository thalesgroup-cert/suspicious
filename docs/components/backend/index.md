# Backend (Django)

The backend is a Django REST API served by Gunicorn (port 9020) with a
Celery worker for background jobs and a separate Celery beat container
(`suspicious_celery_beat`) for the periodic schedule. It is organised into focused
apps; each page below documents one.

| App | Responsibility |
|---|---|
| [api](api.md) | REST endpoints and permissions |
| [case_handler](case_handler.md) | Case CRUD and lifecycle |
| [cortex_job](cortex_job.md) | Cortex orchestration; `Analyzer`, `AnalyzerReport`, `CaseAnalyzerJob` |
| [score_process](score_process.md) | Risk scoring; rule-based verdict explanation and narration prompt-building |
| [connectors](connectors.md) | Plugin framework for external integrations (TheHive, MISP, Watcher, SMTP, ChromaDB, `ai_narration`, `case_search`, `elastic_siem`, `xsoar`, `ai_model`) |
| [ai_model](ai_model.md) | Mail AI model lifecycle: `AiAssessment`, label ledger, model registry, retrain, shadow and promotion; REST under `/api/ai-model/` |
| `common` | Shared infrastructure, no models or routes: object-store providers (`common/storage`: S3-compatible and GCS), cache locks, the circuit-breaker HTTP client, safe-exec helpers and migration utilities |
| [email_process](email_process.md) | Email parsing and submission |
| [Observable processors](observable-processors.md) | domain / url / ip / hash / file analysis |
| [dashboard](dashboard.md) | KPI metrics |
| [mail_feeder](mail_feeder.md) | Outbound SMTP notification templates |
| [tasp](tasp.md) | Celery beat schedule + task wrappers |
| [settings](settings.md) | DB-backed config (blacklists, whitelists, campaigns) |
| [profiles](profiles.md) | User profile management |

`submission_queue` is still in `INSTALLED_APPS` only so its migration can drop
the obsolete table (see [Model conventions](models-guide.md)); it has no code
to document.

Writing or changing a model? Read the [model conventions and safe-change guide](models-guide.md) first.

Code lives under `Suspicious/Suspicious/<app>/`. Selected models and tasks are
auto-documented in the [Python Code Reference](../../reference/index.md).
