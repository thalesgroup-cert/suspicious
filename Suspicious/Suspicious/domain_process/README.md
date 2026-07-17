# 🧳 Domain Process Module

This module is a Django app that manages the domains that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for domain handling.

---

## 📦 Overview

The `domain_process` app:

- Manage Domains through Django models and views
- Provide APIs for CRUD operations on domains
- Offer utility scripts to handle and automate domain creation and handling
- Include mechanisms for updating domain scores and handling their lifecycle

---

## 🧩 Directory Structure

```
domain_process/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── domain_utils/
│   ├── public/
│   │   ├── publicsuffix.org-tlds/
│   │   ├── urls/
│   │   └── public_suffix_list.dat
│   └── domain_handler.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with domains (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `domain_utils/domain_handler.py`
Includes helper functions to programmatically generate and initialize new domains.

### `domain_utils/public/publicsuffix.org-tlds/`
Library used to validate the domains that are submitted against the public list of domains.

### `domain_utils/public/urls/`
Library used to validate the domains that are submitted against the public list of domains.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test domain_process
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'domain_process',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('domain_process.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py file.

```bash
python manage.py makemigrations domain_process
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py file.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.

---

## 📄 License

MIT
