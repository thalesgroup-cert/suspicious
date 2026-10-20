# 🧳 settings Process Module

This module is a Django app that manages the settingss that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for settings handling.

---

## 📦 Overview

The `settings` app:

- Manage settingss through Django models and views
- Provide APIs for CRUD operations on settingss
- Offer utility scripts to handle and automate settings creation and handling
- Include mechanisms for updating settings settingss and handling their lifecycle

---

## 🧩 Directory Structure

```
settings/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with settingss (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `ListChangeLog`
Append-only audit trail of additions and removals on the Settings allow/deny lists. Written by `api/utils/settings_service.py` and exposed at `GET /api/settings/list/<section>/history/`; `added_by` on the list rows comes from the row's own `user`. Only changes made through the Settings API are logged; deleting a user account cascades to the entries that user added (the list tables' `user` FK is `CASCADE`) without a log row. History starts when migration `0013_listchangelog` is applied: earlier removals were not recorded. Details in `docs/components/backend/settings.md`.

### `settings_utils/domain.py`
Handles the domain

### `settings_utils/feeder_email.py`
Handles the feeder email

### `settings_utils/filetype.py`
Handles the filetype

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test settings
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'settings',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('settings.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py settings.

```bash
python manage.py makemigrations settings
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py settings.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.

---

## 📄 License

MIT
