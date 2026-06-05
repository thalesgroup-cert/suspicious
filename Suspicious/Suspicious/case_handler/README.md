# 🧳 Case Handler Module

This module is a Django app that manages and updates cases. It includes standard Django components (models, views, urls) and custom utilities for case creation, handling, and scoring.

---

## 📦 Overview

The `case_handler` app:
- Manage cases through Django models and views
- Provide APIs for CRUD operations on cases
- Offer utility scripts to handle and automate case creation and updating
- Include mechanisms for updating case scores and handling their lifecycle

---

## 🧩 Directory Structure

```
case_handler/
├── admin.py
├── apps.py
├── models.py
├── tests.py
├── urls.py
├── views.py
├── migrations/
│   └── *.py
├── case_utils/
│   ├── case_creator.py
│   └── case_handler.py
├── update_case/
│   ├── update_case.py
│   ├── update_handler.py
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

### `case_utils/form_handlers/mail/`
Includes helper functions to handle user submission of an email using the web form.

### `case_utils/case_creator.py`
Includes helper functions to generate and initialize new cases.

### `case_utils/case_handler.py`
Handles logic for updating or processing existing cases.

### `update_case/update_case.py`
Acts as the entry point for bulk updates or scheduled case management.

### `update_case/update_handler.py`
Contains the business logic for applying updates to cases.

### `update_case/update_score_calculation.py`
Implements score computation logic for cases, possibly based on internal or AI-assessed criteria.

---

## 🧪 Testing

- Located in: `tests.py`
- Use Django's test framework:
```bash
python manage.py test case_handler
```

---

## 🔧 Usage

### Add to Installed Apps
```python
# settings.py
INSTALLED_APPS = [
    ...
    'case_handler',
]
```

### Include URLs
```python
# project/urls.py
path('cases/', include('case_handler.urls')),
```

### Run Migrations
```bash
python manage.py makemigrations case_handler
python manage.py migrate
```

---

## 📌 Notes

- Ensure database schema is up to date with the latest migrations.
- Review AI field updates if integrating external AI processing.
- Extend test coverage for edge-case case handling and update logic.
