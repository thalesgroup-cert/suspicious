import json
import logging
import os
import shutil
import pathlib
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import classes.models.configs.main_config
import classes.services.config_service
import classes.services.minio_service
import classes.services.mailbox_setup_service
import classes.services.mailbox_service
import classes.services.acknowledge_bad_mail_service
import classes.services.logger_service
import classes.services.otel_service

logger = classes.services.logger_service.setup_logging()

# Best-effort OTel init — exporter target read from OTEL_EXPORTER_OTLP_ENDPOINT
# (defaults to http://tempo:4318 in the compose network). Failures inside
# configure() are swallowed: the feeder must boot even if Tempo is down.
classes.services.otel_service.configure(
    service_name="email-feeder",
    enabled=os.environ.get("OTEL_ENABLED", "true").lower() != "false",
)

# ---------------------------------------------------------------------------
# Health / metrics state — written by the poll loop, read by the HTTP server
# ---------------------------------------------------------------------------

_HEALTH_PORT = 9091

# Anything older than this is "stale" — the dependency was reachable at
# some point but has not been touched recently. Keep above the legitimate
# IMAP polling cadence (default 60 s) so a single missed cycle does not
# flip a healthy feeder to degraded.
_HEALTH_STALE_THRESHOLD_S = 5 * 60

_stats: dict = {
    "last_successful_poll": 0.0,   # Unix timestamp; 0 = never polled
    "emails_processed_total": 0,
    "errors_total": 0,
    # name → last unix ts a fetch_unseen_emails_and_process() succeeded.
    # Populated by process_emails_from_mailboxes; consumed by /health.
    "mailbox_last_ok": {},
    # Last unix ts a MinIO upload succeeded.
    "minio_last_ok": 0.0,
    # How many connectors are configured at boot (target).
    "mailboxes_configured": 0,
}
_stats_lock = threading.Lock()


def _inc(key: str, amount: int = 1) -> None:
    with _stats_lock:
        _stats[key] += amount


def _set(key: str, value) -> None:
    with _stats_lock:
        _stats[key] = value


def _mark_mailbox_ok(name: str) -> None:
    """Record that this mailbox last responded successfully at now()."""
    with _stats_lock:
        _stats["mailbox_last_ok"][name] = time.time()


def _mark_minio_ok() -> None:
    """Record that a MinIO operation just succeeded."""
    with _stats_lock:
        _stats["minio_last_ok"] = time.time()


def _build_health_payload() -> dict:
    """Snapshot stats + derive subsystem readiness for /health.

    Connectivity is tracked passively: every successful fetch /
    upload writes a timestamp; /health compares against
    _HEALTH_STALE_THRESHOLD_S. This keeps the endpoint O(1), avoids
    contending with the poll loop, and never opens a side-effect
    connection to IMAP or MinIO from the HTTP thread.
    """
    now = time.time()
    with _stats_lock:
        snap = dict(_stats)
        mailbox_last_ok = dict(snap["mailbox_last_ok"])

    def _stale(ts: float) -> bool:
        return ts <= 0.0 or (now - ts) > _HEALTH_STALE_THRESHOLD_S

    imap_ok_count = sum(1 for ts in mailbox_last_ok.values() if not _stale(ts))
    imap_overall = (
        snap["mailboxes_configured"] > 0
        and imap_ok_count == snap["mailboxes_configured"]
    )
    minio_overall = not _stale(snap["minio_last_ok"])

    status = "ok" if (imap_overall and minio_overall) else "degraded"

    return {
        "status": status,
        "last_successful_poll": snap["last_successful_poll"] or None,
        "emails_processed_total": snap["emails_processed_total"],
        "errors_total": snap["errors_total"],
        "checks": {
            "imap": {
                "ok": imap_overall,
                "configured": snap["mailboxes_configured"],
                "healthy": imap_ok_count,
                "last_ok": {
                    name: int(ts) for name, ts in mailbox_last_ok.items()
                },
            },
            "minio": {
                "ok": minio_overall,
                "last_ok": int(snap["minio_last_ok"]) or None,
            },
        },
        "stale_threshold_seconds": _HEALTH_STALE_THRESHOLD_S,
        "checked_at": int(now),
    }


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return

        body = json.dumps(_build_health_payload(), indent=2).encode()
        # Always 200 once the feeder process is alive — the Docker
        # healthcheck only needs to know the process is responsive.
        # Degradation is surfaced in the JSON `status` field so the
        # Django proxy + UI badge can render an amber state without
        # triggering a container restart.
        self._respond(200, "application/json", body)

    def _respond(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # suppress per-request access logs
        pass


def _start_health_server() -> None:
    server = HTTPServer(("", _HEALTH_PORT), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="health-server")
    thread.start()
    logger.info("Health server listening on :%d (/health)", _HEALTH_PORT)


# --- Helper Functions ---


def cleanup_directory(dir_path: pathlib.Path, remove_parent_if_empty: bool = False):
    """
    Removes a directory and all its contents.
    typing.Optionally removes the parent directory if it becomes empty after this deletion.

    Args:
        dir_path: Path object of the directory to remove.
        remove_parent_if_empty: If True, attempts to remove the parent directory
                                if it's empty after dir_path is removed.
    """
    if not dir_path.exists():
        logger.warning(f"Directory '{dir_path}' not found for cleanup.")
        return None

    try:
        shutil.rmtree(dir_path)
        logger.info(f"Successfully removed directory: {dir_path}")
    except OSError as e:
        logger.error(f"Failed to delete directory '{dir_path}'. Reason: {e}")
    except Exception as e:
        logger.error(
            f"Unexpected error during cleanup of '{dir_path}': {e}", exc_info=True
        )

    if not remove_parent_if_empty:
        return None

    parent_dir = dir_path.parent
    if not parent_dir.exists() or not any(parent_dir.iterdir()):
        return None

    try:
        parent_dir.rmdir()
        logger.info(f"Successfully removed empty parent directory: {parent_dir}")
    except OSError as e:
        logger.warning(
            f"Could not remove parent directory {parent_dir} (it might not be empty or permission issue): {e}"
        )


# --- Email Processing ---


def process_emails_from_mailboxes(
    config: classes.models.configs.main_config.MainConfig,
    acknowledge_bad_mail_service: classes.services.acknowledge_bad_mail_service.AcknowledgeBadMailService,
    mailboxes: list[classes.services.mailbox_service.Mailbox],
    minio_service: classes.services.minio_service.MinioService,
):
    """
    Fetches and processes emails from all enabled mailboxes.
    """
    if not mailboxes:
        logger.info("No mailboxes provided to process.")
        return

    for mailbox in mailboxes:
        mailbox_identifier = mailbox.config.login or mailbox.config.host
        logger.info(f"Checking mailbox: {mailbox_identifier}")
        try:
            email_list = mailbox.fetch_unseen_emails_and_process()

            # IMAP responded — record liveness even when no new mail.
            _mark_mailbox_ok(mailbox_identifier)

            if not email_list:
                logger.info(
                    f"No new emails to process in mailbox: {mailbox_identifier}"
                )
                continue

            logger.info(
                f"Fetched {len(email_list)} email(s) from {mailbox_identifier}."
            )
            _inc("emails_processed_total", len(email_list))
            for mail in email_list:
                case_path = pathlib.Path(mail.case_path)
                acknowledge_bad_mail_service.process_single_email(
                    mail=mail, case_path=case_path
                )

            for case_dir in config.working_path.iterdir():
                if case_dir.is_dir():
                    bucket_name = case_dir.name.lower().replace("_", "-")
                    minio_service.upload_directory(case_dir, bucket_name)
                    _mark_minio_ok()
                    cleanup_directory(case_dir, remove_parent_if_empty=False)
                    logger.info(f"Cleaned up case directory: {case_dir}")

            email_ids = [email.original_mail.id for email in email_list]
            mailbox.mark_emails_as_seen(email_ids=email_ids)
            logger.info(f"Marked emails as seen for mailbox: {mailbox_identifier}.")

        except Exception as e:
            logger.error(
                f"Error processing mailbox {mailbox_identifier}: {e}",
                exc_info=True,
            )
            _inc("errors_total")
        logger.info(f"Finished processing cycle for mailbox: {mailbox_identifier}.")


# --- Main Application Logic ---


def main() -> int:
    """
    Main function to initialize and run the email processing loop.
    """
    logger.info("Application starting...")

    try:
        _backend_url = os.environ.get("BACKEND_URL")
        _api_token = os.environ.get("FEEDER_API_TOKEN")
        _config_path = pathlib.Path(os.environ.get("FEEDER_CONFIG_PATH", "config.json"))
        _cache_path = _config_path.parent / ".config-cache.json"

        if _backend_url and _api_token:
            config = classes.services.config_service.load_config_from_api(
                _backend_url, _api_token, _config_path, _cache_path
            )
        else:
            config = classes.services.config_service.load_config(_config_path, logger)
        if not config:
            logger.critical("Configuration could not be loaded. Exiting.")
            return 1
    except FileNotFoundError:
        logger.critical("Configuration file (e.g., config.json) not found. Exiting.")
        return 1
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}", exc_info=True)
        return 1

    acknowledge_bad_mail_service = (
        classes.services.acknowledge_bad_mail_service.AcknowledgeBadMailService(
            config=config.mail,
            # Acknowledgement-mail send activity -> smtp.log + json stdout.
            logger=logging.getLogger("email-feeder.smtp"),
        )
    )

    minio_service = classes.services.minio_service.MinioService(config.minio)
    try:
        minio_service.connect()
        logger.info("MinIO client initialized from config.")
        # Initial MinIO connect counts as a fresh liveness signal — the
        # /health endpoint will surface this until the next upload.
        _mark_minio_ok()
    except Exception as e:
        logger.critical(f"Failed to initialize MinIO client from config: {e}")
        return 1

    try:
        logger.info("Setting up mailboxes...")
        mailboxes = classes.services.mailbox_setup_service.setup_mailboxes(
            config=config,
            logger=logger,
        )
        if not mailboxes:
            logger.warning(
                "No mailboxes configured or failed to connect. Check logs from setup_mailboxes. Exiting."
            )
            return 1
        logger.info(f"Successfully connected to {len(mailboxes)} mailboxes.")
        _set("mailboxes_configured", len(mailboxes))
        # Mailboxes successfully connected at setup time — seed the
        # per-mailbox liveness map so /health does not report stale
        # before the first poll cycle completes.
        for mailbox in mailboxes:
            _mark_mailbox_ok(mailbox.config.login or mailbox.config.host)
    except Exception as e:
        logger.critical(f"Failed to setup mailboxes: {e}", exc_info=True)
        return 1

    try:
        config.working_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using case processing path: {config.working_path}")
    except OSError as e:
        logger.error(
            f"Could not create or access case processing path '{config.working_path}': {e}. Check permissions."
        )
        return 1

    sleep_interval = config.timer_inbox_emails
    if sleep_interval <= 0:
        default_interval = classes.models.configs.main_config.DEFAULT_SLEEP_INTERVAL
        logger.warning(
            "Invalid 'timer-inbox-emails' value (%s). Using default: %ss.",
            sleep_interval, default_interval,
        )
        sleep_interval = default_interval

    _start_health_server()

    logger.info(f"Starting email processing loop. Interval: {sleep_interval}s")
    try:
        while True:
            logger.info("Starting new email processing cycle...")
            process_emails_from_mailboxes(
                config=config,
                acknowledge_bad_mail_service=acknowledge_bad_mail_service,
                mailboxes=mailboxes,
                minio_service=minio_service,
            )
            _set("last_successful_poll", time.time())
            logger.info(
                f"Email processing cycle complete. Sleeping for {sleep_interval}s."
            )
            time.sleep(sleep_interval)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down application...")
    except Exception as e:
        logger.critical(
            f"An unexpected critical error occurred in the main loop: {e}",
            exc_info=True,
        )
        return 1

    logger.info("Application finished.")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
