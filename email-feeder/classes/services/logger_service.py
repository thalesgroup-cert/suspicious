"""
Logger setup for the email-feeder.

Declarative `logging.config.dictConfig`, mirroring the Django service
(`Suspicious/Suspicious/suspicious/settings.py` LOGGING) so the two stay
diffable. Emits structured JSON (python-json-logger) to stdout AND to
per-domain rotating files. Every record carries `trace_id` / `span_id`
injected by TraceIdFilter so feeder events join Suspicious + Cortex traces
in Tempo without manual correlation.

Domains (child loggers of `email-feeder`):
    email-feeder        -> feeder.log   (lifecycle, config, errors)
    email-feeder.imap   -> imap.log     (login / search / fetch / seen)
    email-feeder.minio  -> minio.log    (bucket ensure / upload)
    email-feeder.smtp   -> smtp.log     (acknowledgement mail send)

Every logger ALSO writes JSON to stdout so `docker logs feeder` /
`make logs s=feeder` carry the full INFO stream — the previous setup only
sent ERROR to the console, leaving operators blind.

Env toggles:
    LOG_LEVEL   INFO (default) | DEBUG | WARNING | ...   (loggers + handlers)
    LOG_FORMAT  json (default) | plain                   (console only; files stay json)
    LOG_DIR     /app/log (default)                       (directory for the files)
    FEEDER_TESTING  1 -> disable file handlers (NullHandler), stdout only

Rotation is in-process (RotatingFileHandler, 10 MiB x 5). No external
logrotate required.

Closes audit O5 (docs/superpowers/specs/2026-05-06-audit/observability.md).
"""
from __future__ import annotations

import logging
import logging.config
import os
import pathlib

DEFAULT_LOGGER_NAME = "email-feeder"
DEFAULT_LOG_DIR = "/app/log"

# domain -> file basename. Each becomes an `email-feeder.<domain>` child logger.
_DOMAIN_FILES: dict[str, str] = {
    "imap": "imap.log",
    "minio": "minio.log",
    "smtp": "smtp.log",
}
_ROOT_FILE = "feeder.log"

_ROTATE_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB, matches Django app_file
_ROTATE_BACKUPS = 5


def _resolve_level() -> str:
    """LOG_LEVEL env (validated) → upper-case level name, default INFO."""
    name = os.environ.get("LOG_LEVEL", "INFO").upper()
    return name if isinstance(logging.getLevelName(name), int) else "INFO"


def _resolve_log_dir() -> pathlib.Path | None:
    """Return a writable log directory, or None when files must be disabled.

    Files are disabled (None) when FEEDER_TESTING is set or when LOG_DIR
    cannot be created / written — so unit tests and local runs never raise
    on a missing /app/log.
    """
    if os.environ.get("FEEDER_TESTING", "").strip().lower() in ("1", "true", "yes"):
        return None

    log_dir = pathlib.Path(os.environ.get("LOG_DIR", DEFAULT_LOG_DIR))
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        probe = log_dir / ".write-test"
        probe.touch()
        probe.unlink()
        return log_dir
    except OSError:
        return None


def _rotating_file_handler(path: pathlib.Path, level: str) -> dict:
    return {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(path),
        "maxBytes": _ROTATE_MAX_BYTES,
        "backupCount": _ROTATE_BACKUPS,
        "encoding": "utf-8",
        "formatter": "json",
        "filters": ["trace_id"],
        "level": level,
    }


def _build_dict_config(log_dir: pathlib.Path | None, level: str, console_fmt: str) -> dict:
    """Assemble the dictConfig. When log_dir is None every file handler is a
    NullHandler (test / unwritable-dir mode)."""

    def file_handler(basename: str) -> dict:
        if log_dir is None:
            return {"class": "logging.NullHandler"}
        return _rotating_file_handler(log_dir / basename, level)

    handlers: dict = {
        "json_stdout": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": console_fmt,
            "filters": ["trace_id"],
            "level": level,
        },
        "feeder_file": file_handler(_ROOT_FILE),
    }
    for domain, basename in _DOMAIN_FILES.items():
        handlers[f"{domain}_file"] = file_handler(basename)

    loggers: dict = {
        DEFAULT_LOGGER_NAME: {
            "handlers": ["feeder_file", "json_stdout"],
            "level": level,
            "propagate": False,
        },
    }
    for domain in _DOMAIN_FILES:
        loggers[f"{DEFAULT_LOGGER_NAME}.{domain}"] = {
            "handlers": [f"{domain}_file", "json_stdout"],
            "level": level,
            "propagate": False,
        }

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            # Structured JSON — consumed by log aggregators (ELK, Loki, etc.).
            # Mirrors the Django service formatter for cross-service consistency.
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": "%(levelname)s %(asctime)s %(name)s %(message)s "
                          "%(trace_id)s %(span_id)s",
            },
            # Plain-text fallback for local tailing (LOG_FORMAT=plain).
            "plain": {
                "format": "%(asctime)s UTC %(name)s %(levelname)s "
                          "trace=%(trace_id)s %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%S",
            },
        },
        "filters": {
            "trace_id": {
                "()": "classes.services.otel_service.TraceIdFilter",
            },
        },
        "handlers": handlers,
        "loggers": loggers,
    }


def setup_logging(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """Configure feeder logging via dictConfig and return the root logger.

    Idempotent-ish: dictConfig with disable_existing_loggers=False can be
    re-run safely (e.g. in tests).
    """
    level = _resolve_level()
    console_fmt = "plain" if os.environ.get("LOG_FORMAT", "json").lower() == "plain" else "json"
    log_dir = _resolve_log_dir()

    logging.config.dictConfig(_build_dict_config(log_dir, level, console_fmt))

    logger = logging.getLogger(logger_name)
    if log_dir is None and not os.environ.get("FEEDER_TESTING"):
        # Surface the degraded state on stdout so it is not silently lost.
        logger.warning(
            "Log directory unavailable (LOG_DIR=%s); file logging disabled, "
            "stdout only.",
            os.environ.get("LOG_DIR", DEFAULT_LOG_DIR),
        )
    return logger


def get_logger(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """Retrieve a logger instance by name; assumes setup_logging() ran first."""
    return logging.getLogger(logger_name)
