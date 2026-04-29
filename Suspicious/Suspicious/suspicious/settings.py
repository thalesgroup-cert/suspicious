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
from urllib.parse import urlparse
import logging
from drf_spectacular.utils import OpenApiParameter

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
_minio      = _storage.get("s3", {})
_integr     = _config.get("integrations", {})
_cortex     = _integr.get("cortex", {})
_chromadb   = _integr.get("chromadb", {})
_features   = _config.get("features", {})
_email_cfg  = _config.get("email", {})
_redis_cfg  = _config.get("redis", {})
_observ  = _config.get("observability", {})
_otel    = _observ.get("opentelemetry", {})

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
    _cortex_hostname = urlparse(_cortex_url).hostname
    if _cortex_hostname:
        ALLOWED_HOSTS.append(_cortex_hostname)

# Shared secret for the Cortex → Suspicious job-completion webhook.
# Set in settings.json under integrations.cortex.webhook_secret.
# If absent, the webhook endpoint rejects all requests.
CORTEX_WEBHOOK_SECRET: str = _cortex.get("webhook_secret", "")

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
    "django_prometheus",
    "rest_framework",
    "drf_spectacular",
    "drf_spectacular_sidecar",  # serves swagger-ui assets locally
    "knox",
    "django_filters",
    "django_celery_results",
    "import_export",
    "fontawesomefree",
 
    # Internal apps (unchanged)
    "suspicious.apps.SuspiciousConfig",
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
    "submission_queue.apps.SubmissionQueueConfig",
]

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
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

    # Optional read-replica — opt-in via settings.json `database.replica`.
    # When present, reads from apps listed in REPLICA_READ_APPS route to
    # this alias; writes always stay on "default". See suspicious.db_router.
    _db_replica = _db.get("replica") or {}
    if _db_replica:
        DATABASES["replica"] = {
            "ENGINE":   "django.db.backends.mysql",
            "NAME":     _db_replica.get("name", _db["name"]),
            "USER":     _db_replica.get("user", _db["user"]),
            "PASSWORD": _db_replica.get("password", _db["password"]),
            "HOST":     _db_replica.get("host", "db_suspicious_replica"),
            "PORT":     _db_replica.get("port", _db.get("port", "3306")),
            "OPTIONS":  {"charset": "utf8mb4"},
        }
        if _db_opts.get("ssl"):
            DATABASES["replica"]["OPTIONS"]["ssl"] = {"ca": "/cert.pem"}
        if _db_opts.get("connection_pooling"):
            DATABASES["replica"]["CONN_MAX_AGE"] = None
        elif _db_opts.get("persistent_connections"):
            DATABASES["replica"]["CONN_MAX_AGE"] = 600

        DATABASE_ROUTERS = ["suspicious.db_router.PrimaryReplicaRouter"]
        REPLICA_READ_APPS = tuple(
            _db.get("replica_read_apps", ["dashboard", "case_handler"])
        )

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Cache — Redis (redis_cache container)
# ---------------------------------------------------------------------------

_redis_cache_host = _redis_cfg.get("cache_host", "redis_cache")

if "test" in sys.argv:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": f"redis://{_redis_cache_host}:6379/0",
        }
    }

# ---------------------------------------------------------------------------
# Sessions — Redis cache backend (eliminates per-request DB session lookup)
#
# The OIDC callback view stores state/nonce in the session between the
# login redirect and the provider callback, so the session backend must
# be functional even for unauthenticated requests.
# ---------------------------------------------------------------------------

SESSION_ENGINE               = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS          = "default"
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
        # Keep the local user record in sync with the directory on every
        # login (name/email changes propagate automatically).
        AUTH_LDAP_ALWAYS_UPDATE_USER = True

        # Cache LDAP group memberships for 1 hour so repeated requests
        # don't re-query the directory on every login attempt.
        AUTH_LDAP_CACHE_TIMEOUT = 3600
 
        # Reuse the LDAP connection across requests instead of opening a
        # new TCP connection for every authentication call.
        # This is the most impactful setting for latency — without it,
        # each LDAP auth pays a full TCP handshake + bind RTT.
        AUTH_LDAP_CONNECTION_OPTIONS = {
            ldap.OPT_NETWORK_TIMEOUT: 5,    # fail fast if LDAP is unreachable
            ldap.OPT_TIMEOUT:         10,   # total operation timeout
        }

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
        # Cookie auth first — used by the browser SPA (httpOnly cookie, XSS-safe).
        # Falls through when the cookie is absent so API clients can still
        # authenticate via Authorization: Token <token>.
        "api.authentication.KnoxCookieAuthentication",
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
# OpenTelemetry
# ---------------------------------------------------------------------------

OTEL_ENABLED                 = _otel.get("enabled", False)
OTEL_SERVICE_NAME            = _otel.get("service_name", "suspicious")
OTEL_EXPORTER_OTLP_ENDPOINT  = _otel.get("otlp_endpoint", "http://tempo:4318")

# ---------------------------------------------------------------------------
# Knox (token auth)
# ---------------------------------------------------------------------------

REST_KNOX = {
    "SECURE_HASH_ALGORITHM": "hashlib.sha3_512",
    "TOKEN_TTL": timedelta(hours=10),
    # Rotate tokens: if a request arrives within TOKEN_TTL/2, extend it.
    "AUTO_REFRESH": False,
}

# ---------------------------------------------------------------------------
# drf-spectacular (OpenAPI schema)
# ---------------------------------------------------------------------------

SPECTACULAR_SETTINGS = {
    "TITLE": "Suspicious API",
    "DESCRIPTION": "Suspicious — security intake and automated analysis platform.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
 
    # Serve Swagger UI assets from the sidecar package (local /static/)
    # instead of cdn.jsdelivr.net. Required because the production CSP
    # blocks external script/style/img sources.
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
 
    "SECURITY": [{"TokenAuth": []}],
    "COMPONENTS": {
        "securitySchemes": {
            "TokenAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
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

if _storage_backend in {"s3", "dual"}:
    INSTALLED_APPS.append("minio_storage")

    MINIO_STORAGE_ENDPOINT      = _minio.get("endpoint",   "rustfs:9000")
    MINIO_STORAGE_ACCESS_KEY    = _minio["access_key"]
    MINIO_STORAGE_SECRET_KEY    = _minio["secret_key"]
    MINIO_STORAGE_USE_HTTPS = bool(_minio.get("secure", False))
    MINIO_STORAGE_MEDIA_BUCKET_NAME = _minio.get("media_bucket", "suspicious-media")
    MINIO_STORAGE_AUTO_CREATE_MEDIA_BUCKET = True

_DUAL_WRITE = str(_features.get("dual_storage_write", "0")).lower()

if _storage_backend == "s3":
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

DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_UPLOAD_SIZE  # cap in-memory multipart parsing
FILE_UPLOAD_MAX_MEMORY_SIZE = 0               # always spool uploads to disk
SUBMIT_FILE_MAX_BYTES       = MAX_UPLOAD_SIZE  # serializer-level guard; keep in sync

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
# Celery — broker (redis_broker container) + result backend (MariaDB)
# ---------------------------------------------------------------------------

from celery.schedules import crontab  # noqa: E402 — intentional mid-file import for BEAT_SCHEDULE

_redis_broker_host = _redis_cfg.get("broker_host", "redis_broker")

CELERY_BROKER_URL         = f"redis://{_redis_broker_host}:6379/0"
CELERY_RESULT_BACKEND     = "django-db"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_SERIALIZER    = "json"
CELERY_ACCEPT_CONTENT     = ["json"]
CELERY_TIMEZONE           = _app.get("timezone", "UTC")

if "test" in sys.argv:
    CELERY_TASK_ALWAYS_EAGER    = True
    CELERY_TASK_EAGER_PROPAGATES = True

CELERY_BEAT_SCHEDULE = {
    "fetch-emails": {
        "task": "tasp.tasks.fetch_emails",
        "schedule": 60.0,
    },
    "sync-cortex": {
        "task": "tasp.tasks.sync_cortex",
        "schedule": 60.0,
    },
    "update-ongoing-cases": {
        "task": "tasp.tasks.update_ongoing_cases",
        "schedule": 60.0,
    },
    "check-challengeable": {
        "task": "tasp.tasks.check_challengeable",
        "schedule": crontab(hour=0, minute=0),
    },
    "sync-monthly-kpi": {
        "task": "tasp.tasks.sync_monthly_kpi",
        "schedule": 300.0,
    },
    "sync-user-profiles": {
        "task": "tasp.tasks.sync_user_profiles",
        "schedule": 600.0,
    },
    "delete-old-reports": {
        "task": "tasp.tasks.delete_old_reports",
        "schedule": crontab(day_of_month=1, hour=0, minute=0),
    },
    "remove-old-emails": {
        "task": "tasp.tasks.remove_old_emails",
        "schedule": crontab(hour=0, minute=0),
    },
    "watcher-sync": {
        "task": "tasp.tasks.watcher_sync",
        "schedule": 300.0,
    },
    "materialise-dashboard-snapshots": {
        "task": "tasp.tasks.materialise_dashboard_snapshots",
        "schedule": crontab(hour=2, minute=0),
    },
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_trace_level = getattr(logging, _app.get("log_level", "INFO").upper(), logging.INFO)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        # Structured JSON — consumed by log aggregators (ELK, Loki, etc.).
        # Fields: level, time, logger, message, plus any extra= keys passed
        # at the call site (e.g. user_id, case_id on audit events).
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(levelname)s %(asctime)s %(name)s %(message)s %(trace_id)s %(span_id)s",
        },
        # Plain-text fallback kept for local development / docker logs tailing.
        "verbose": {
            "format": "%(levelname)s %(asctime)s | %(name)s | %(message)s",
        },
    },

    "filters": {
        "trace_id": {
            "()": "suspicious.otel.TraceIdFilter",
        },
    },

    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "verbose",
        },
        "json_console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["trace_id"],
        },
        "app_file": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/suspicious.log",
            "maxBytes":  10 * 1024 * 1024,   # 10 MB
            "backupCount": 5,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "fetch_mail": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/fetched_mail.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "update_cases": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/case_updating.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "fetch_analyzer": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/fetch_analyzer.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "cleanup": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/cleanup_phishing.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "watcher_sync": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/watcher_sync.log",
            "maxBytes":  10 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters":   ["trace_id"],
            "level":     _trace_level,
        },
        "audit": {
            "class":     "logging.handlers.RotatingFileHandler",
            "filename":  "/app/log/cert_downloads.log",
            "maxBytes":  50 * 1024 * 1024,
            "backupCount": 10,
            "formatter": "json",
            "filters":   ["trace_id"],
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
            "handlers": ["app_file", "json_console"],
            "level":     _trace_level,
            "propagate": False,
        },
        "case_handler": {
            "handlers":  ["app_file", "json_console"],
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
            "handlers":  ["json_console"],
            "level":     _trace_level,
            "propagate": False,
        },

        # Audit trail for certificate downloads
        "audit.cert_download": {
            "handlers":  ["audit"],
            "level":     _trace_level,
            "propagate": False,
        },
    },
}