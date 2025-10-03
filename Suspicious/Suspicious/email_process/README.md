# 🧳 Email Process Module

This module is part of a Django-based application that provides functionality to manage the emails that are submitted to suspicious either via mail or simple submission. It includes standard Django components (models, views, urls) and custom utilities for email handling.

---

## 📦 Overview

The `email_process` app is designed to:

- Manage emails through Django models and views
- Provide APIs for CRUD operations on emails
- Offer utility scripts to handle and automate email creation and handling
- Include mechanisms for updating email scores and handling their lifecycle

---

## 🧩 Directory Structure

```
email_process/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── email_utils/
│   └── email_handler.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with emails (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `email_utils/email_handler.py`
Includes helper functions to programmatically generate and initialize new emails.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test email_process
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'email_process',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('email_process.urls')),
```

### Make Migrations

Making migration is mandatory if you have pushed an altered version of the models.py file.

```bash
python manage.py makemigrations email_process
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
