# 🧳 Score Process Module

This module is a Django app that manages the scores that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for score handling.

---

## 📦 Overview

The `score_process` app:

- Manage scores through Django models and views
- Provide APIs for CRUD operations on scores
- Offer utility scripts to handle and automate score creation and handling
- Include mechanisms for updating score scores and handling their lifecycle

---

## 🧩 Directory Structure

```
score_process/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── score_utils/
│   ├── templates/
│   ├── chromadb_utils.py
│   ├── send_mail.py
│   ├── thehive.py
│   ├── update_thehive.py
│   └── utils.py
├── scoring/
│   ├── case_score_calculation.py
│   ├── case_update.py
│   ├── header_parser.py
│   ├── misp.py
│   ├── processing.py
│   ├── score_check.py
│   └── updating.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with scores (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `score_utils/chromadb_utils.py`


---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test score_process
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'score_process',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('score_process.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py score.

```bash
python manage.py makemigrations score_process
```

### Run Migrations

Running migration is mandatory if you want to have the modification you have altered version of the models.py score.

```bash
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.

---

## 📄 License

MIT
