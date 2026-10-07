import logging

audit_logger = logging.getLogger("audit.cert_download")


def log_cert_download(*, user, case_id, object_name, ip):
    audit_logger.info(
        "CERT_DOWNLOAD",
        extra={
            "username": user.username,
            "case_id": case_id,
            "object_name": object_name,
            "ip_address": ip,
        },
    )


thehive_audit_logger = logging.getLogger("audit.thehive_push")


def log_thehive_push(*, user, case_id, alert_id, outcome, ip, error=""):
    """One line per manual TheHive push (outcome: created | updated | failed)."""
    thehive_audit_logger.info(
        "THEHIVE_PUSH",
        extra={
            "username": user.username,
            "case_id": case_id,
            "alert_id": alert_id or "",
            "outcome": outcome,
            "ip_address": ip,
            "error": error,
        },
    )
