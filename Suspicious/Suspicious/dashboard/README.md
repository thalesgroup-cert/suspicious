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
├── snapshot.py          # nightly DashboardSnapshot writer (Overall)
├── tests.py
├── tests_regional.py    # live summary + B1 regression
├── urls.py
├── migrations/
│   └── *.py
├── dash_utils/
│   ├── dashboard.py
│   └── regional.py      # live summary behind /api/dashboard/summary/
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `dash_utils/dashboard.py`
Handles logic for updating or processing existing dashboard.

### `dash_utils/regional.py` (live summary)
`summarise(month, year, group_names, include_names=False)` aggregates `Case` live for one month,
restricted to reporters in **every** group of `group_names` (country code, region, GBU; `None` = Overall).
It backs `GET /api/dashboard/summary/` (cached 120 s per month/year/scope) and the nightly
`DashboardSnapshot` for Overall (written by the 02:00 beat task, read by nothing at present). The
summary no longer reads the monthly stats tables.

- A report counts in the month its case was created, in the server timezone (same bucket as the
  Investigation list's date filter).
- `outcomes` (safe, inconclusive, suspicious, dangerous, failure) count only cases with status
  Done or Challenged; `in_progress` counts To Do and On Going (a running case's default
  `Inconclusive` is not an outcome).
- `by_type` uses the Investigation type vocabulary (MAIL, FILE, URL, IP, HASH, IOC, UNKNOWN).
- `previous` holds `reports` and `outcomes` of the preceding month; `trend` lists reports per
  ISO week (Monday start, so the first week can start in the previous month), `[]` when empty.
- `top_reporters` is filled only when the caller passes `include_names` (see Scopes), `null` otherwise:
  one entry per user, labelled by email local part (the full username where two local parts collide).
  The `SUSPICIOUS_EMAIL` mailbox is excluded from it and from `reporters`.

### Scopes (`api/permissions/dashboard_scope.py`)
`GET /api/dashboard/scopes/` lists what the caller may request; `resolve_scope` enforces it
server-side (anything else is a 403):

| Key | Who |
|---|---|
| `ALL` (Overall) | everyone |
| `OWN_COUNTRY` | anyone whose profile has a country (default for them) |
| `OWN_SCOPE` | CISO with a scope set on their CISOProfile (their default) |
| `COUNTRY:<CC>`, `REGION:<NAME>` | CERT, Admin, superuser (options list profile countries/regions) |

`OWN_COUNTRY` requires both the LDAP-synced profile country and the Django group of that name
(profile `country`/`region`/`gbu` are read-only in the API; the LDAP sync sets both). Users created
by OIDC login only have neither until the LDAP sync fills them, so they get Overall only. A CISO's
own stored scope string (e.g. `AU`, `AU|Off GBU`, `AU | Off GBU`, compared after split/strip) is
accepted as an alias of `OWN_SCOPE` (compared as a set, so order does not matter). A CISO scope
counts only when the CISO is in every group it names. Reporter names (`top_reporters`) go to
CERT/Admin/superuser, and to a CISO only for `OWN_SCOPE`. The old `/api/stats/top-prefixes/`
ranking and the summary's legacy `kpis`, `danger_counts` and `top_prefixes` keys are removed.

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
