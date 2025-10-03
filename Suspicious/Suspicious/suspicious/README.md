# 🧳 Suspicious app

This app is part of a Django-based application that provides functionality to manage the overall app.

---

## 📦 Overview

The main APP.

---

## 🧩 Directory Structure

```
suspicious/
├── asgi.py
├── settings.py
├── urls.py
└── wsgi.py
```

---

## ⚙️ Key Components

### `settings.py`
Defines the settings of the main app.

### `asgi.py`
Handles the main HTTP endpoints for interacting with scores (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

### `urls.py`
Maps URL patterns to views for routing HTTP requests within the app.

### `wsgi.py`
Handles the main HTTP endpoints for interacting with scores (e.g., create, retrieve, update). Likely implements Django REST Framework views or standard Django views.

---

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
