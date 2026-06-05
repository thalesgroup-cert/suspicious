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
