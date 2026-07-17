# 🧳 Profile Module

This module is a Django app that manages and updates profiles. It includes standard Django components (models, views, urls) and custom utilities for profile creation, handling, and scoring.

---

## 📦 Overview

The `profile` app:
- Manage cases through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate profile creation and updating
- Include mechanisms for updating profiles and handling their lifecycle

---

## 🧩 Directory Structure

```
profile/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── profile_utils/
│   ├── ciso.py
│   └── ldap.py
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

### `profile_utils/ciso.py`
Handles the CISO profiles

### `profile_utils/ldap.py`
Handles the LDAP profiles

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test profile
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'profile',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('profile.urls')),
```

### Run Migrations
```bash
python manage.py makemigrations profile
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
