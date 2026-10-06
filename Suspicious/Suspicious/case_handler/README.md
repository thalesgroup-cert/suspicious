# 🧳 Case Handler Module

This module is a Django app that manages and updates cases. It includes standard Django components (models, views, urls) and custom utilities for case creation, handling, and scoring.

---

## 📦 Overview

The `case_handler` app:
- Manage cases through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate case creation and updating
- Include mechanisms for updating case scores and handling their lifecycle

---

## 🧩 Directory Structure

```
case_handler/
├── admin.py
├── apps.py
├── models.py
├── lifecycle.py            # LifecycleState choices + transition() state machine
├── urls.py
├── tests/                  # test_case_verdict_explanation_field.py, test_lifecycle_*.py, etc.
├── management/commands/
│   └── heal_orphaned_cases.py
├── case_utils/
│   ├── case_creator.py
│   ├── case_handler.py
│   └── form_handlers/mail/   # web-form email submission (converters, parser, saver)
```

There is no `views.py` here — case CRUD/detail endpoints live in the `api` app,
which wraps this app's models.

---

## ⚙️ Key Components

### `models.py`
The `Case` model and its related entities. Beyond the obvious scoring fields
(`status`, `results`, `final_score`, `final_confidence`), notable ones:
- `lifecycle_state` — drives the `case_handler.lifecycle` state machine (see below)
- `verdict_rationale` (`JSONField`, list) — the older, free-text rationale lines
- `verdict_explanation` (`JSONField`, nullable) — the newer, structured
  rule-based explanation (`band`, `confidence`, `decisive_rule`,
  `analyst_paragraph`, `reporter_paragraph`, `confidence_reading`, `sources`),
  composed by `score_process.scoring.explanation`. Every render surface falls
  back to `verdict_rationale` / a generic guidance string when this is null
  (historical cases, or a case scored before the field existed).
- `is_challenged` / `challenge_proposed_result` / `challenge_reason` — the
  reporter challenge-a-verdict workflow, plus its own `CaseChallengeToken` model
- `is_allowlisted` / `is_denylisted` / `list_reason` — org allow/deny-list hits
- `thehive_alert_id`, `kpi_counted` — connector/dashboard bookkeeping

Related models in the same file: `CaseChallengeToken`, `CaseComment`,
`CaseHasFileOrMail`, `CaseHasNonFileIocs`, `ObservableGroup` (and its
`ObservableGroupArtifact`s).

### `lifecycle.py`
`LifecycleState` (the case's actual state machine, distinct from `results` —
the verdict band) and `transition()`, the only sanctioned way to move a case
between states.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `case_utils/form_handlers/mail/`
Includes helper functions to handle user submission of an email using the web form.

### `case_utils/case_creator.py`
Includes helper functions to generate and initialize new cases.

### `case_utils/case_handler.py`
Handles logic for updating or processing existing cases.

Score computation itself lives in `score_process`, not here — this app owns
the `Case` record and its lifecycle, not the scoring math.

---

## 🧪 Testing

- Located in: `tests/` (a package, not a single `tests.py`)
- Use Django's test framework:
```bash
python manage.py test case_handler
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'case_handler',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('case_handler.urls')),
```

### Run Migrations
```bash
python manage.py makemigrations case_handler
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
- Review AI field updates if integrating external AI processing.
- Extend test coverage for edge-case case handling and update logic.
