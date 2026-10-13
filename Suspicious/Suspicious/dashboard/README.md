# 🧳 Dashboard Module

This module is a Django app that manages the KPIs and the Dashboard page of the app. It includes standard Django components (models, views, urls) and custom utilities for kpi handling.

---

## 📦 Overview

The `dashboard` app:

- Manage KPIs through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate dashboard creation and handling
- Include mechanisms for updating dashboard scores and handling their lifecycle

---

## 🧩 Directory Structure

```
dashboard/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── dash_utils/
│   ├── utils.py
│   └── dashboard.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with dashboard(e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `dash_utils/utils.py`
Includes helper functions to programmatically generate and initialize new dashboard.

### `dash_utils/dashboard.py`
Handles logic for updating or processing existing dashboard.

### `dash_utils/regional.py` (live summary)
`summarise(month, year, group_names, include_names=False)` aggregates `Case` live for one month,
restricted to reporters in **every** group of `group_names` (country code, region, GBU; `None` = Overall).
It backs `GET /api/dashboard/summary/` (cached 120 s per month/year/scope) and the nightly
`DashboardSnapshot` for Overall. The summary no longer reads the monthly stats tables.

- A report counts in the month its case was created, in the server timezone (same bucket as the
  Investigation list's date filter).
- `outcomes` (safe, inconclusive, suspicious, dangerous, failure) count only cases with status
  Done or Challenged; `in_progress` counts To Do and On Going (a running case's default
  `Inconclusive` is not an outcome).
- `by_type` uses the Investigation type vocabulary (MAIL, FILE, URL, IP, HASH, IOC, UNKNOWN).
- `previous` holds `reports` and `outcomes` of the preceding month; `trend` lists reports per
  ISO week (Monday start, so the first week can start in the previous month), `[]` when empty.
- `top_reporters` is filled only for CERT/Admin/CISO callers, `null` otherwise.

### Scopes (`api/permissions/dashboard_scope.py`)
`GET /api/dashboard/scopes/` lists what the caller may request; `resolve_scope` enforces it
server-side (anything else is a 403):

| Key | Who |
|---|---|
| `ALL` (Overall) | everyone |
| `OWN_COUNTRY` | anyone whose profile has a country (default for them) |
| `OWN_SCOPE` | CISO with a scope set on their CISOProfile (their default) |
| `COUNTRY:<CC>`, `REGION:<NAME>` | CERT, Admin, superuser (options list profile countries/regions) |

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test dashboard
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'dashboard',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('dashboard.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py file.

```bash
python manage.py makemigrations dashboard
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py file.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
- Extend test coverage for edge-case dashboard handling and update logic.

---

## 📄 License

MIT
