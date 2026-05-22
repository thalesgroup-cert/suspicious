# Backend (Django)

The backend is a Django REST API served by Gunicorn (port 9020) with a
companion Celery worker for background jobs. It is organised into focused
apps; each page below documents one.

| App | Responsibility |
|---|---|
| [api](api.md) | REST endpoints and permissions |
| [case_handler](case_handler.md) | Case CRUD and lifecycle |
| [cortex_job](cortex_job.md) | Cortex orchestration; `Analyzer`, `AnalyzerReport`, `CaseAnalyzerJob` |
| [score_process](score_process.md) | Risk scoring, TheHive/MISP, ChromaDB |
| [email_process](email_process.md) | Email parsing and submission |
| [Observable processors](observable-processors.md) | domain / url / ip / hash / file analysis |
| [dashboard](dashboard.md) | KPI metrics |
| [mail_feeder](mail_feeder.md) | Outbound SMTP notification templates |
| [submission_queue](submission_queue.md) | Async job queue |
| [tasp](tasp.md) | Celery beat schedule + task wrappers |
| [settings](settings.md) | DB-backed config (blacklists, whitelists, campaigns) |
| [profiles](profiles.md) | User profile management |

Code lives under `Suspicious/Suspicious/<app>/`. Selected models and tasks are
auto-documented in the [Python Code Reference](../../reference/index.md).
