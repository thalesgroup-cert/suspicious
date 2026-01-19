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
