"""Fast path: build EmailDataModel from the feeder's email.json when present,
valid and integrity-checked; otherwise fall back to parse_email on the .eml."""
import email
import json
import logging
import os

from mail_feeder import email_contract as ec
from mail_feeder.email_parser.parser import parse_email
from mail_feeder.email_parser.from_metadata import (
    build_email_data_model, MetadataIntegrityError,
)

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


def fast_metadata_enabled() -> bool:
    try:
        from settings.config import get_section
        return bool((get_section("storage.s3") or {}).get("fast_metadata", False))
    except Exception:
        return False


def load_email_data(workdir: str, filename: str, email_id: str, reported_by: str):
    meta_path = os.path.join(workdir, ec.EMAIL_METADATA_OBJECT_NAME)
    if fast_metadata_enabled() and os.path.isfile(meta_path):
        try:
            with open(meta_path, "rb") as f:
                meta = ec.EmailMetadata.model_validate(json.loads(f.read()))
            return build_email_data_model(
                meta, reported_by, os.path.join(workdir, "attachments"))
        except (MetadataIntegrityError, Exception) as e:
            logger.warning("Fast metadata path failed for %s (%s); falling back to "
                           "parse_email", email_id, e)
    with open(os.path.join(workdir, filename), "rb") as f:
        msg = email.message_from_bytes(f.read())
    return parse_email(msg, workdir, email_id, reported_by)
