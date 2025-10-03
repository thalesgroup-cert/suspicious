# 🧳 Cortex Job Module

This module is part of a Django-based application that provides functionality to manage Cortex Analyzers and its jobs. It includes standard Django components (models, views, urls) and custom utilities for job creation, handling.

---

## 📦 Overview

The `cortex_job` app is designed to:
- Manage cortex jobs through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate cortex jobs creation and handling
- Include mechanisms for creating and launching jobs and handling their lifecycle

---

## 🧩 Directory Structure

```
cortex_job/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── cortex_utils/
│   └── cortex_and_job_management.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with cortex jobs (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `cortex_utils/cortex_and_job_management.py`
Includes helper functions to programmatically generate and initialize new cortex jobs depending on the type of artifact or attachment.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test cortex_job
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'cortex_job',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('cortex_job.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py file.

```bash
python manage.py makemigrations cortex_job
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py file.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
- Extend test coverage for edge-case case handling and update logic.

---

## 📄 License

MIT
