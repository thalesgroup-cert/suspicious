# 🧳 Mail Feeder Module

This module is part of a Django-based application that provides functionality to manage and update mail instance. It includes standard Django components (models, views, urls) and custom utilities for mail creation, handling, and scoring.

---

## 📦 Overview

The `mail_feeder` app is designed to:
- Manage cases through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate mail creation and updating
- Include mechanisms for updating mail scores and handling their lifecycle

---

## 🧩 Directory Structure

```
mail_feeder/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── processor/
│   └── email_processor.py
├── mail_utils/
│   ├── mail.py
│   ├── mail_handler.py
│   ├── meioc.py
│   ├── outlookmsgfile.py
│   ├── similarity_hash.py
│   └── update_score_calculation.py
```

---

## ⚙️ Key Components

### `models.py`
Defines the data structures for cases and related entities.

### `views.py`
Handles the main HTTP endpoints for interacting with cases (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `admin.py`
Registers the models for Django admin interface.

### `processor/email_processor.py`
Helps in the process of emails

### `mail_utils/mail.py`
Create and redirect to handler

### `mail_utils/mail_handler.py`
Handles the mail instances and their lifecycle

### `mail_utils/meioc.py`
Library to extract observables from mail

### `mail_utils/similarity_hash.py`
Looks for similarity between two mail headers or body using fuzzy hashing

### `mail_utils/update_score_calculation.py`
Calculate the score of emails

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test mail_feeder
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'mail_feeder',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('mail_feeder.urls')),
```

### Run Migrations
```bash
python manage.py makemigrations mail_feeder
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
