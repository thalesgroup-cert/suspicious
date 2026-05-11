"""
Logger setup for the email-feeder.

Emits structured JSON (python-json-logger) to stdout + file when the
optional dependency is installed, falling back to plain-text format
otherwise. Every record carries `trace_id` / `span_id` injected by
TraceIdFilter so feeder events join Suspicious + Cortex traces in
Tempo without manual correlation.

Format toggle via env:
    LOG_FORMAT=json   (default)
    LOG_FORMAT=plain  (local tailing)

Closes audit O5 (docs/superpowers/specs/2026-05-06-audit/observability.md).
"""
from __future__ import annotations

import logging
import os
import sys
import time

from classes.services.otel_service import TraceIdFilter

DEFAULT_LOGGER_NAME = "email-feeder"
DEFAULT_LOG_FILE = "application.log"


def _build_formatter(prefer_json: bool) -> logging.Formatter:
    """Return a JSON formatter when python-json-logger is available."""
    if prefer_json:
        try:
            from pythonjsonlogger import jsonlogger  # type: ignore[import-not-found]
            return jsonlogger.JsonFormatter(
                fmt="%(levelname)s %(asctime)s %(name)s %(message)s "
                    "%(trace_id)s %(span_id)s",
                rename_fields={"asctime": "time", "levelname": "level"},
            )
        except ImportError:
            # python-json-logger is optional — fall through to plain.
            pass

    plain = logging.Formatter(
        fmt="%(asctime)s UTC %(name)s %(levelname)s "
            "trace=%(trace_id)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    plain.converter = time.gmtime
    return plain


def setup_logging(
    logger_name: str = DEFAULT_LOGGER_NAME,
    log_file: str = DEFAULT_LOG_FILE,
    file_log_level: int = logging.INFO,
    console_log_level: int = logging.ERROR,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> logging.Logger:
    """Configure the feeder logger with JSON formatter + TraceIdFilter."""
    logger = logging.getLogger(logger_name)

    logger.setLevel(
        min(file_log_level, console_log_level)
        if log_to_file and log_to_console
        else (
            file_log_level
            if log_to_file
            else console_log_level
            if log_to_console
            else logging.WARNING
        )
    )

    if logger.hasHandlers():
        logger.handlers.clear()

    fmt_choice = os.environ.get("LOG_FORMAT", "json").lower()
    formatter = _build_formatter(prefer_json=(fmt_choice == "json"))
    trace_filter = TraceIdFilter()

    if log_to_file:
        try:
            file_handler = logging.FileHandler(
                filename=log_file, mode="a", encoding="utf-8"
            )
            file_handler.setLevel(file_log_level)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(trace_filter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(
                f"Error setting up file logger at {log_file}: {e}. "
                "Logging to console instead.",
                file=sys.stderr,
            )
            if not log_to_console:
                log_to_console = True
                console_log_level = logging.INFO

    if log_to_console:
        stdout_handler = logging.StreamHandler(stream=sys.stdout)
        stdout_handler.setLevel(console_log_level)
        stdout_handler.setFormatter(formatter)
        stdout_handler.addFilter(trace_filter)
        logger.addHandler(stdout_handler)

    if not log_to_file and not log_to_console:
        logger.addHandler(logging.NullHandler())
        print(
            f"Warning: Logger '{logger_name}' has no handlers configured "
            "(file or console).",
            file=sys.stderr,
        )

    return logger


def get_logger(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """Retrieve a logger instance by name; assumes setup_logging() ran first."""
    return logging.getLogger(logger_name)
