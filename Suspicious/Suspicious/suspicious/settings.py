# suspicious/settings.py
#
# Production-ready settings for the Suspicious platform.
#
# Configuration is loaded from /app/settings.json, which is split into
# top-level sections:
#
#   suspicious  — app-level config (host, secret key, OIDC, storage, …)
#   database    — MySQL connection parameters
#   ldap        — optional LDAP / Active Directory auth
#   minio       — optional MinIO object storage
#   cortex      — Cortex analyzer host
#
# All sensitive values (SECRET_KEY, DB password, OIDC secret, LDAP bind
# password) must live in settings.json and never be committed to version
# control.  The file is mounted at runtime by your container orchestrator.
#
# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import json
import sys
from datetime import timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Load configuration file
# ---------------------------------------------------------------------------

CONFIG_PATH = "/app/settings.json"

with open(CONFIG_PATH) as _f:
    _config = json.load(_f)

_app        = _config.get("app", {})
_db         = _config.get("database", {})
_auth       = _config.get("authentication", {})
_ldap_cfg   = _auth.get("ldap", {})
_oidc       = _auth.get("oidc", {})
_storage    = _config.get("storage", {})
_minio      = _storage.get("minio", {})
_integr     = _config.get("integrations", {})
_cortex     = _integr.get("cortex", {})
_chromadb   = _integr.get("chromadb", {})
_features   = _config.get("features", {})
_email_cfg  = _config.get("email", {})

# ---------------------------------------------------------------------------
# Base directories
# ---------------------------------------------------------------------------

# BASE_DIR  → repository root  (settings.py is 3 levels deep: suspicious/settings.py)
BASE_DIR       = Path(__file__).resolve().parent.parent.parent
# FILES_BASE_DIR → project root (one level up from suspicious/)
FILES_BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

SECRET_KEY = _app["secret_key"]

_debug_raw = _app.get("debug", False)
DEBUG = str(_debug_raw).lower() not in {"false", "0", "no", "off"}

ALLOWED_HOSTS = _app.get("allowed_hosts", ["localhost"]) + [
    "127.0.0.1",
    "localhost",
]
# Add the Cortex host if provided (needed for internal callbacks)
_cortex_url = _cortex.get("url", "")
if _cortex_url:
    ALLOWED_HOSTS.append(_cortex_url)

# CSRF — at least one trusted origin is required for POST requests in
# Django 4.x.  Must be a full scheme+host (e.g. https://suspicious.corp).
CSRF_TRUSTED_ORIGINS = _app.get("csrf_trusted_origins", ["https://localhost"])

# Reverse-proxy headers — the proxy must set these explicitly.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST   = True

# Enforce HTTPS in production (no-op when DEBUG is True).
if not DEBUG:
    SECURE_SSL_REDIRECT            = True
    SECURE_HSTS_SECONDS            = 31_536_000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD            = True
    SESSION_COOKIE_SECURE          = True
    CSRF_COOKIE_SECURE             = True

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    # Django built-ins
    "django.contrib.admin",
    "django.contrib.admindocs",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",

    # Third-party
    "rest_framework",
    "drf_spectacular",
    "knox",
    "django_filters",
    "django_crontab",
    "import_export",
    "fontawesomefree",

    # Internal apps
    "api.apps.ApiConfig",
    "tasp.apps.TaspConfig",
    "dashboard.apps.DashboardConfig",
    "case_handler.apps.CaseConfig",
    "cortex_job.apps.CortexConfig",
    "domain_process.apps.DomainConfig",
    "email_process.apps.EmailConfig",
    "file_process.apps.FileConfig",
    "hash_process.apps.HashConfig",
    "ip_process.apps.IPConfig",
    "mail_feeder.apps.MailFeederConfig",
    "profiles.apps.ProfilesConfig",
    "settings.apps.SettingsConfig",
    "url_process.apps.URLConfig",
    "score_process.apps.ScoreConfig",
    "submission_queue.apps.SubmissionQueueConfig"
]

MIDDLEWARE = [
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF    = "suspicious.urls"
WSGI_APPLICATION = "suspicious.wsgi.application"
ASGI_APPLICATION = "suspicious.asgi.application"

SITE_ID = 1

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [FILES_BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

if "test" in sys.argv:
    # Use SQLite in-memory for the test suite — no MySQL required.
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME":   ":memory:",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE":   "django.db.backends.mysql",
            "NAME":     _db["name"],
            "USER":     _db["user"],
            "PASSWORD": _db["password"],
            "HOST":     _db.get("host", "localhost"),
            "PORT":     _db.get("port", "3306"),
            "OPTIONS":  {"charset": "utf8mb4"},
        }
    }
    _db_opts = _db.get("options", {})
    # Optional SSL
    if _db_opts.get("ssl"):
        DATABASES["default"]["OPTIONS"]["ssl"] = {"ca": "/cert.pem"}

    # Optional connection pooling / persistence
    if _db_opts.get("connection_pooling"):
        DATABASES["default"]["CONN_MAX_AGE"] = None       # persistent
    elif _db_opts.get("persistent_connections"):
        DATABASES["default"]["CONN_MAX_AGE"] = 600        # 10 min pool

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Sessions
#
# The OIDC callback view stores state/nonce in the session between the
# login redirect and the provider callback, so the session backend must
# be functional even for unauthenticated requests.
# ---------------------------------------------------------------------------

SESSION_ENGINE               = "django.contrib.sessions.backends.db"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY      = True     # prevent JS access
SESSION_COOKIE_SAMESITE      = "Lax"   # CSRF protection; Strict breaks OIDC redirects

# ---------------------------------------------------------------------------
# Authentication backends
#
# Order matters: LDAP is tried first; if the user isn't found there,
# Django's model backend is used (covers superusers and OIDC-created users).
# ---------------------------------------------------------------------------

AUTHENTICATION_BACKENDS = []

_ldap_uri = _ldap_cfg.get("server_uri")
if _ldap_uri:
    # Only wire up LDAP when a server is actually configured.
    # This avoids ImportError / connection errors on setups that use
    # pure OIDC or local accounts only.
    try:
        import ldap
        from django_auth_ldap.config import LDAPSearch

        AUTH_LDAP_SERVER_URI      = _ldap_uri
        AUTH_LDAP_BIND_DN         = _ldap_cfg.get("bind_dn", "")
        AUTH_LDAP_BIND_PASSWORD   = _ldap_cfg.get("bind_password", "")
        AUTH_LDAP_USER_SEARCH     = LDAPSearch(
            _ldap_cfg["base_dn"],
            ldap.SCOPE_SUBTREE,
            _ldap_cfg.get("filter", "(uid=%(user)s)"),
        )
        AUTH_LDAP_USER_ATTR_MAP   = {
            "first_name": "givenName",
            "last_name":  "sn",
            "email":      "mail",
        }
        AUTH_LDAP_ALWAYS_UPDATE_USER = True
        AUTH_LDAP_CACHE_TIMEOUT      = 3600

        _verify_ssl = str(_ldap_cfg.get("verify_ssl", "False")).lower()
        if _verify_ssl in ("false", "0", "no"):
            AUTH_LDAP_GLOBAL_OPTIONS = {
                ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER
            }

        AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")
    except ImportError:
        pass  # python-ldap not installed — skip silently

AUTHENTICATION_BACKENDS.append("django.contrib.auth.backends.ModelBackend")

# ---------------------------------------------------------------------------
# OIDC (custom Authorization Code flow — see api/views/oidc.py)
#
# These settings are consumed by OIDCLoginView and OIDCCallbackView.
# allauth / mozilla-django-oidc are NOT used; the OIDC flow is
# implemented directly so Knox tokens are issued at the callback.
#
# OIDC_REDIRECT_URI is optional: if absent, the callback view derives it
# from the request using build_absolute_uri("/oidc/callback/"), which
# works correctly when SECURE_PROXY_SSL_HEADER and USE_X_FORWARDED_HOST
# are set.
# ---------------------------------------------------------------------------

OIDC_SERVER_URL    = _oidc.get("server_url", "")
OIDC_CLIENT_ID     = _oidc.get("client_id", "")
OIDC_CLIENT_SECRET = _oidc.get("client_secret", "")
OIDC_SCOPES        = _oidc.get("scopes", "openid email profile")
OIDC_REDIRECT_URI  = _oidc.get("redirect_uri", "")

# Note: SOCIALACCOUNT_PROVIDERS (allauth) is removed — allauth is not in
# INSTALLED_APPS and the custom OIDC views do not use it.

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "knox.auth.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "login": "5/min",
    },
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# ---------------------------------------------------------------------------
# Knox (token auth)
# ---------------------------------------------------------------------------

REST_KNOX = {
    "SECURE_HASH_ALGORITHM": "cryptography.hazmat.primitives.hashes.SHA3_512",
    "TOKEN_TTL": timedelta(hours=10),
    # Rotate tokens: if a request arrives within TOKEN_TTL/2, extend it.
    "AUTO_REFRESH": False,
}

# ---------------------------------------------------------------------------
# drf-spectacular (OpenAPI schema)
# ---------------------------------------------------------------------------

SPECTACULAR_SETTINGS = {
    "TITLE":               "Suspicious API",
    "DESCRIPTION":         "Suspicious — security intake and automated analysis platform.",
    "VERSION":             "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SECURITY": [{"TokenAuth": []}],
    "COMPONENTS": {
        "securitySchemes": {
            "TokenAuth": {
                "type":        "apiKey",
                "in":          "header",
                "name":        "Authorization",
                "description": "Format: Token <your_api_token>",
            }
        }
    },
}

# ---------------------------------------------------------------------------
# Storage backend
#
# Three modes, set via suspicious.storage_backend in settings.json:
#   local  — standard Django FileSystemStorage (default)
#   minio  — MinIO object storage via django-minio-storage
#   dual   — write to both MinIO and local (useful during migrations)
# ---------------------------------------------------------------------------

_storage_backend = _storage.get("backend", "local").lower()

if _storage_backend in {"minio", "dual"}:
    INSTALLED_APPS.append("minio_storage")

    MINIO_STORAGE_ENDPOINT      = _minio.get("endpoint",   "minio:9000")
    MINIO_STORAGE_ACCESS_KEY    = _minio["access_key"]
    MINIO_STORAGE_SECRET_KEY    = _minio["secret_key"]
    MINIO_STORAGE_USE_HTTPS = bool(_minio.get("secure", False))
    MINIO_STORAGE_MEDIA_BUCKET_NAME = _minio.get("media_bucket", "suspicious-media")
    MINIO_STORAGE_AUTO_CREATE_MEDIA_BUCKET = True

_DUAL_WRITE = str(_features.get("dual_storage_write", "0")).lower()

if _storage_backend == "minio":
    DEFAULT_FILE_STORAGE = "minio_storage.storage.MinioMediaStorage"
elif _storage_backend == "dual" or (_storage_backend == "local" and _DUAL_WRITE):
    DEFAULT_FILE_STORAGE = "suspicious.storage_backends.DualStorage"
else:
    DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"

# ---------------------------------------------------------------------------
# Static and media files
# ---------------------------------------------------------------------------

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
STATIC_URL  = "/static/"
STATIC_ROOT = FILES_BASE_DIR / "static"

MEDIA_URL  = "/media/"
MEDIA_ROOT = FILES_BASE_DIR / "media"

# ---------------------------------------------------------------------------
# File uploads
# ---------------------------------------------------------------------------

FILE_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]

MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB — enforced at the serializer level

# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 9},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = _app.get("timezone", "UTC")
USE_I18N      = True
USE_L10N      = True
USE_TZ        = True

# ---------------------------------------------------------------------------
# Submission groups
# ---------------------------------------------------------------------------

# Groups whose members receive elevated permissions in the API
# (access to CISO/CERT-only routes).
SUBMISSION_ELEVATED_GROUPS = ("CERT", "CISO", "Admin")

# ---------------------------------------------------------------------------
# Cron jobs
# ---------------------------------------------------------------------------

CRONTAB_LOCK_JOBS = True   # prevent overlapping runs

CRONJOBS = [
    ("*/1 * * * *",  "tasp.cron.fetch_emails.fetch_and_process_emails",       ">> /app/log/fetched_mail.log"),
    ("*/1 * * * *",  "tasp.cron.sync_cortex.sync_cortex_analyzers"),
    ("*/1 * * * *",  "tasp.cron.user_and_cases.update_ongoing_case_jobs",     ">> /app/log/case_updating.log"),
    ("0 0 * * *",    "tasp.cron.suspicious.check_challengeable",              ">> /app/log/case_challengeable.log"),
    ("*/5 * * * *",  "tasp.cron.kpi.sync_monthly_kpi"),
    ("*/10 * * * *", "tasp.cron.user_and_cases.sync_user_profiles"),
    ("0 0 1 * *",    "tasp.cron.cleanup.delete_old_analyzer_reports",         ">> /app/log/cleanup_phishing.log"),
    ("0 0 * * *",    "tasp.cron.suspicious.remove_old_suspicious_emails",     ">> /app/log/cleanup_phishing.log"),
    ("*/5 * * * *",  "tasp.cron.watcher.run_watcher_sync",                   ">> /app/log/watcher_sync.log"),
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_trace_level = _app.get("log_level", "INFO").upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "verbose": {
            "format":  "{levelname} {asctime} | {name} | {message}",
            "style":   "{",
        },
        "simple": {
            "format":  "{levelname} {message}",
            "style":   "{",
        },
    },

    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "verbose",
        },
        "app_file": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/suspicious.log",
            "maxBytes":  10 * 1024 * 1024,   # 10 MB
            "backupCount": 5,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "fetch_mail": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/fetched_mail.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "update_cases": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/case_updating.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "fetch_analyzer": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/fetch_analyzer.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "cleanup": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/cleanup_phishing.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "watcher_sync": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/watcher_sync.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "verbose",
            "level":     _trace_level,
        },
        "audit": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/var/log/cert_downloads.log",
            "maxBytes":  50 * 1024 * 1024,
            "backupCount": 10,
            "formatter": "verbose",
            "level":     "INFO",
        },
    },

    "loggers": {
        # Django internals — only errors to console (avoid noise)
        "django": {
            "handlers": ["console"],
            "level":    "ERROR",
            "propagate": False,
        },

        # Main application
        "tasp": {
            "handlers":  ["app_file", "console"],
            "level":     _trace_level,
            "propagate": False,
        },
        "case_handler": {
            "handlers":  ["app_file", "console"],
            "level":     _trace_level,
            "propagate": False,
        },

        # OIDC views — useful to see callback errors in the main log
        "api.views.oidc_views": {
            "handlers":  ["app_file", "console"],
            "level":     _trace_level,
            "propagate": False,
        },

        # Cron sub-loggers
        "tasp.cron.fetch_and_process_emails": {
            "handlers":  ["fetch_mail"],
            "level":     _trace_level,
            "propagate": False,
        },
        "tasp.cron.update_ongoing_case_jobs": {
            "handlers":  ["update_cases"],
            "level":     _trace_level,
            "propagate": False,
        },
        "tasp.cron.fetch_analyzer": {
            "handlers":  ["fetch_analyzer"],
            "level":     _trace_level,
            "propagate": False,
        },
        "tasp.cron.cleanup_phishing": {
            "handlers":  ["cleanup"],
            "level":     _trace_level,
            "propagate": False,
        },
        "tasp.cron.watcher": {
            "handlers":  ["watcher_sync"],
            "level":     _trace_level,
            "propagate": False,
        },

        # LDAP debug (can be very verbose — consider raising to WARNING)
        "django_auth_ldap": {
            "handlers":  ["console"],
            "level":     _trace_level,
            "propagate": False,
        },

        # Audit trail for certificate downloads
        "audit.cert_download": {
            "handlers":  ["audit"],
            "level":     "INFO",
            "propagate": False,
        },
    },
}