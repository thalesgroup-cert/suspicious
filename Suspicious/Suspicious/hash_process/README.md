# 🧳 Hash Process Module

This module is part of a Django-based application that provides functionality to manage the hashs that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for hash handling.

---

## 📦 Overview

The `hash_process` app is designed to:

- Manage hashs through Django models and views
- Provide APIs for CRUD operations on hashs
- Offer utility scripts to handle and automate hash creation and handling
- Include mechanisms for updating hash scores and handling their lifecycle

---

## 🧩 Directory Structure

```
hash_process/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── hash_utils/
│   └── hash_handler.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with hashs (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `hash_utils/hash_handler.py`
Includes helper functions to programmatically generate and initialize new hashs.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test hash_process
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'hash_process',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('hash_process.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py hash.

```bash
python manage.py makemigrations hash_process
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py hash.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.

---

## 📄 License

MIT
