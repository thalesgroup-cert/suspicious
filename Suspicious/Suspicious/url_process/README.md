# 🧳 Url Process Module

This module is part of a Django-based application that provides functionality to manage the urls that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for url handling.

---

## 📦 Overview

The `url_process` app is designed to:

- Manage urls through Django models and views
- Provide APIs for CRUD operations on urls
- Offer utility scripts to handle and automate url creation and handling
- Include mechanisms for updating url scores and handling their lifecycle

---

## 🧩 Directory Structure

```
url_process/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── url_utils/
│   └── url_handler.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with urls (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `url_utils/url_handler.py`
Includes helper functions to programmatically generate and initialize new urls.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test url_process
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'url_process',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('url_process.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py url.

```bash
python manage.py makemigrations url_process
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py url.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.

---

## 📄 License

MIT
