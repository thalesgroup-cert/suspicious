
import json
import sys
import warnings
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse
import logging

warnings.filterwarnings("ignore", category=SyntaxWarning, module=r"spf$")
warnings.filterwarnings("ignore", category=SyntaxWarning, module=r"simhash(\..*)?$")

# ---------------------------------------------------------------------------
# Load configuration file
# ---------------------------------------------------------------------------

import os as _os
CONFIG_PATH = _os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")

_is_test = (
    "test" in sys.argv
    or not _os.path.isdir("/app/log")
)

with open(CONFIG_PATH) as _f:
    _config = json.load(_f)

from suspicious.config_schema import validate_config, ConfigValidationError

try:
    _config = validate_config(_config, source=CONFIG_PATH)
except ConfigValidationError as exc:
    sys.stderr.write(f"\nFATAL: {exc}\n\n")
    raise SystemExit(1)

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

BASE_DIR       = Path(__file__).resolve().parent.parent.parent
FILES_BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

from suspicious.secrets import get_secret

SECRET_KEY = get_secret("app.secret_key", fail_fast=True)

_debug_raw = _app.get("debug", False)
DEBUG = str(_debug_raw).strip().lower() in {"true", "1", "yes", "on"}

ALLOWED_HOSTS = _app.get("allowed_hosts", ["localhost"]) + [
    "127.0.0.1",
    "localhost",
]
_cortex_url = _cortex.get("url", "")
if _cortex_url:
    _cortex_hostname = urlparse(_cortex_url).hostname
    if _cortex_hostname:
        ALLOWED_HOSTS.append(_cortex_hostname)

CORTEX_WEBHOOK_SECRET: str = get_secret("integrations.cortex.webhook_secret", "")

CSRF_TRUSTED_ORIGINS = _app.get("csrf_trusted_origins", ["https://localhost"])

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST   = True

if not DEBUG:
    SECURE_SSL_REDIRECT            = True
    SECURE_HSTS_SECONDS            = 31_536_000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD            = True
    SESSION_COOKIE_SECURE          = True
    CSRF_COOKIE_SECURE             = True

from django.core.exceptions import ImproperlyConfigured

if SECRET_KEY in ("", "CHANGE_ME"):
    raise ImproperlyConfigured(
        "app.secret_key is unset or still the placeholder 'CHANGE_ME'; "
        "generate a unique random key."
    )

if not DEBUG:
    if "*" in ALLOWED_HOSTS:
        raise ImproperlyConfigured(
            "ALLOWED_HOSTS must not contain '*' in production; "
            "set app.allowed_hosts to explicit hostnames."
        )
    if SECRET_KEY.startswith("django-insecure") or len(SECRET_KEY) < 50:
        raise ImproperlyConfigured(
            "app.secret_key is too weak for production: drop the "
            "'django-insecure' prefix and use at least 50 random characters."
        )

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.admindocs",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",

    "rest_framework",
    "drf_spectacular",
    "knox",
    "django_filters",
    "django_celery_results",
    "import_export",
    "fontawesomefree",

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
    "connectors.apps.ConnectorsConfig",
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

if _is_test:
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
            "PASSWORD": get_secret("database.password", fail_fast=True),
            "HOST":     _db.get("host", "localhost"),
            "PORT":     _db.get("port", "3306"),
            "OPTIONS":  {"charset": "utf8mb4"},
        }
    }
    _db_opts = _db.get("options", {})
    if _db_opts.get("ssl"):
        DATABASES["default"]["OPTIONS"]["ssl"] = {"ca": "/cert.pem"}

    if _db_opts.get("connection_pooling"):
        DATABASES["default"]["CONN_MAX_AGE"] = None
    elif _db_opts.get("persistent_connections"):
        DATABASES["default"]["CONN_MAX_AGE"] = 600

    _db_replica = _db.get("replica") or {}
    if _db_replica:
        DATABASES["replica"] = {
            "ENGINE":   "django.db.backends.mysql",
            "NAME":     _db_replica.get("name", _db["name"]),
            "USER":     _db_replica.get("user", _db["user"]),
            "PASSWORD": _db_replica.get("password") or get_secret("database.password", fail_fast=True),
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

if _is_test:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": f"redis://{_redis_cache_host}:6379/0",
        }
    }

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

SESSION_ENGINE               = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS          = "default"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY      = True
SESSION_COOKIE_SAMESITE      = "Lax"

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

AUTHENTICATION_BACKENDS = []

_ldap_uri = _ldap_cfg.get("server_uri")
if _ldap_uri:
    try:
        import ldap
        from django_auth_ldap.config import LDAPSearch

        AUTH_LDAP_SERVER_URI      = _ldap_uri
        AUTH_LDAP_BIND_DN         = _ldap_cfg.get("bind_dn", "")
        AUTH_LDAP_BIND_PASSWORD   = get_secret("authentication.ldap.bind_password", "")
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

        AUTH_LDAP_CACHE_TIMEOUT = 3600
 
        AUTH_LDAP_CONNECTION_OPTIONS = {
            ldap.OPT_NETWORK_TIMEOUT: 5,
            ldap.OPT_TIMEOUT:         10,
        }

        _verify_ssl = str(_ldap_cfg.get("verify_ssl", "True")).lower()
        if _verify_ssl in ("false", "0", "no"):
            logging.getLogger("suspicious.boot").warning(
                "LDAP TLS verification disabled via settings.json "
                "(integrations.ldap.verify_ssl=false). Bind credentials "
                "are exposed to MITM. Set verify_ssl=true and supply a "
                "trusted CA bundle for production."
            )
            AUTH_LDAP_GLOBAL_OPTIONS = {
                ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER,
            }
        else:
            AUTH_LDAP_GLOBAL_OPTIONS = {
                ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_DEMAND,
            }

        AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")
    except ImportError:
        pass

AUTHENTICATION_BACKENDS.append("django.contrib.auth.backends.ModelBackend")

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

OIDC_SERVER_URL    = _oidc.get("server_url", "")
OIDC_CLIENT_ID     = _oidc.get("client_id", "")
OIDC_CLIENT_SECRET = get_secret("authentication.oidc.client_secret", "")
OIDC_SCOPES        = _oidc.get("scopes", "openid email profile")
OIDC_REDIRECT_URI  = _oidc.get("redirect_uri", "")


# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "api.authentication.KnoxCookieAuthentication",
        "knox.auth.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_RENDERER_CLASSES": (
        ["rest_framework.renderers.JSONRenderer"]
        + (["rest_framework.renderers.BrowsableAPIRenderer"] if DEBUG else [])
    ),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "login": "5/min",
        "service_config": "30/min",
        "user": "3000/hour",
        "anon": "100/hour",
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
# ---------------------------------------------------------------------------

_storage_backend = _storage.get("backend", "local").lower()
_DUAL_WRITE = str(_features.get("dual_storage_write", "0")).strip().lower() in {
    "1", "true", "yes", "on",
}

if _storage_backend in {"s3", "dual"}:
    MINIO_STORAGE_ENDPOINT      = _minio.get("endpoint",   "rustfs:9000")
    MINIO_STORAGE_ACCESS_KEY    = _minio["access_key"]
    MINIO_STORAGE_SECRET_KEY    = get_secret("storage.s3.secret_key", _minio.get("secret_key", ""))
    MINIO_STORAGE_USE_HTTPS = bool(_minio.get("secure", False))
    MINIO_STORAGE_MEDIA_BUCKET_NAME = _minio.get("media_bucket", "suspicious-media")
    MINIO_STORAGE_AUTO_CREATE_MEDIA_BUCKET = True
    SUSPICIOUS_STORAGE_DUAL_WRITE = _DUAL_WRITE

if _storage_backend == "s3":
    _default_file_backend = "suspicious.storage_backends.MinioMediaStorage"
elif _storage_backend == "dual" or (_storage_backend == "local" and _DUAL_WRITE):
    _default_file_backend = "suspicious.storage_backends.DualStorage"
else:
    _default_file_backend = "django.core.files.storage.FileSystemStorage"

# ---------------------------------------------------------------------------
# Static and media files
# ---------------------------------------------------------------------------

STORAGES = {
    "default": {"BACKEND": _default_file_backend},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

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

MAX_UPLOAD_SIZE = 5 * 1024 * 1024

DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_UPLOAD_SIZE
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
SUBMIT_FILE_MAX_BYTES       = MAX_UPLOAD_SIZE

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

SUBMISSION_ELEVATED_GROUPS = ("CERT", "CISO", "Admin")

# ---------------------------------------------------------------------------
# Celery — broker (redis_broker container) + result backend (MariaDB)
# ---------------------------------------------------------------------------

from celery.schedules import crontab

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
        "schedule": 300.0,
    },
    "fail-stale-jobs": {
        "task": "tasp.tasks.fail_stale_jobs",
        "schedule": 600.0,
    },
    "sweep-missing-mail-previews": {
        "task": "tasp.tasks.sweep_missing_mail_previews",
        "schedule": 600.0,
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
    "materialise-dashboard-snapshots": {
        "task": "tasp.tasks.materialise_dashboard_snapshots",
        "schedule": crontab(hour=2, minute=0),
    },
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_trace_level = getattr(logging, _app.get("log_level", "INFO").upper(), logging.INFO)

APP_LOGGERS = [
    "api", "case_handler", "cortex_job", "score_process", "connectors",
    "mail_feeder", "email_process", "url_process", "ip_process",
    "hash_process", "file_process", "domain_process", "dashboard",
    "settings", "profiles", "tasp", "suspicious",
]
assert len(APP_LOGGERS) == len(set(APP_LOGGERS)), "duplicate name in APP_LOGGERS"


def _app_logger(name: str) -> tuple[dict, dict]:
    """Build the (handler, logger) pair for one Django app's dedicated log
    file. Plain per-app log? Add the name to APP_LOGGERS above. Need a
    different handler/rotation/name mapping (a cross-cutting pipeline
    logger)? Write it by hand below, unchanged — don't force it through
    this generator."""
    handler = (
        {"class": "logging.NullHandler"}
        if _is_test
        else {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"/app/log/{name}.log",
            "maxBytes": 5 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "json",
            "filters": ["trace_id"],
            "level": _trace_level,
        }
    )
    logger = {
        "handlers": [f"{name}_file", "json_console"],
        "level": _trace_level,
        "propagate": False,
    }
    return handler, logger


_app_handlers: dict = {}
_app_loggers: dict = {}
for _app_name in APP_LOGGERS:
    _handler, _logger = _app_logger(_app_name)
    _app_handlers[f"{_app_name}_file"] = _handler
    _app_loggers[_app_name] = _logger

_unclassified_handler = (
    {"class": "logging.NullHandler"}
    if _is_test
    else {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": "/app/log/unclassified.log",
        "maxBytes": 5 * 1024 * 1024,
        "backupCount": 3,
        "formatter": "json",
        "filters": ["trace_id"],
        "level": _trace_level,
    }
)

if _is_test:
    _file_handlers: dict = {
        name: {"class": "logging.NullHandler"}
        for name in ("fetch_mail", "update_cases",
                     "fetch_analyzer", "cleanup", "watcher_sync", "audit")
    }
else:
    _file_handlers = {
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
    }

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(levelname)s %(asctime)s %(name)s %(message)s %(trace_id)s %(span_id)s",
        },
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
        **_file_handlers,
        **_app_handlers,
        "unclassified_file": _unclassified_handler,
    },

    "loggers": {
        **_app_loggers,

        "django": {
            "handlers": ["console"],
            "level":    "ERROR",
            "propagate": False,
        },

        "api.views.oidc_views": {
            "handlers":  ["suspicious_file", "console"],
            "level":     _trace_level,
            "propagate": False,
        },

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
        "connectors.contrib.watcher": {
            "handlers":  ["watcher_sync"],
            "level":     _trace_level,
            "propagate": False,
        },

        "django_auth_ldap": {
            "handlers":  ["json_console"],
            "level":     _trace_level,
            "propagate": False,
        },

        "audit.cert_download": {
            "handlers":  ["audit"],
            "level":     _trace_level,
            "propagate": False,
        },
    },

    "root": {
        "handlers": ["unclassified_file", "json_console"],
        "level": "WARNING",
    },
}