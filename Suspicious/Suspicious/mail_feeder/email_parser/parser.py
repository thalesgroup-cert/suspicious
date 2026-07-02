import os
import logging
from email.message import Message
from email.utils import getaddresses
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from mail_feeder import email_contract as ec
from .utils import decode_email_header, ensure_dir
from .models import EmailDataModel, AttachmentModel

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


def _safe_attachment_destination(
    save_dir: str, filename: str
) -> Optional[Tuple[Path, str]]:
    """Confine an attachment write to save_dir.

    MIME attachment filenames are attacker-controlled and must never be
    used as a path: os.path.join(save_dir, "/abs/path") silently discards
    save_dir, and "../" escapes it. Reduce to a basename, reject empty /
    dot names, then verify the resolved path is still inside save_dir.
    """
    base_dir = Path(save_dir).resolve()
    safe_filename = os.path.basename(os.path.normpath(filename))
    if not safe_filename or safe_filename in {".", ".."}:
        return None

    destination = (base_dir / safe_filename).resolve()
    try:
        destination.relative_to(base_dir)
    except ValueError:
        return None

    return destination, safe_filename


# -------------------------
# Helpers
# -------------------------

def extract_first_email(header_value: str) -> Optional[str]:
    if not header_value:
        return None

    addresses = getaddresses([header_value])
    for _, email in addresses:
        if email:
            return email.lower()

    return None


def decode_and_extract(header: Optional[str]) -> Optional[str]:
    decoded = decode_email_header(header or "")
    return extract_first_email(decoded)


# -------------------------
# Attachments
# -------------------------

def extract_email_attachments(
    email_message: Message,
    save_dir: str,
    email_reference: str
) -> List[AttachmentModel]:

    attachments: List[AttachmentModel] = []

    for part in email_message.walk():
        if part.get_content_maintype() == "multipart":
            continue

        content_disposition = part.get("Content-Disposition", "")
        if "attachment" not in content_disposition.lower():
            continue

        raw_filename = part.get_filename()
        if not raw_filename:
            continue

        decoded_filename = ec.decode_header_value(raw_filename)
        destination = _safe_attachment_destination(save_dir, decoded_filename)
        if destination is None:
            logger.warning(
                f"Skipping attachment with unsafe filename: {decoded_filename!r}"
            )
            continue

        filepath, safe_filename = destination

        try:
            payload = part.get_payload(decode=True)

            with open(filepath, "wb") as f:
                f.write(payload)

            attachments.append(
                AttachmentModel(
                    filename=safe_filename,
                    content=payload,
                    headers={k: ec.decode_header_value(v) for k, v in part.items()},
                    parent=email_reference
                )
            )

        except Exception as e:
            logger.error(f"Failed to save attachment {safe_filename}: {e}")

    return attachments


# -------------------------
# Headers
# -------------------------

def get_header_dict_list(email_message: Message) -> Dict[str, str]:
    return {
        k: ec.decode_header_value(v)
        for k, v in email_message.items()
    }


# -------------------------
# Main parser
# -------------------------

def parse_email(
    email_message: Message,
    working_dir: str,
    email_reference: str,
    reported_by: Optional[str]
) -> EmailDataModel:

    ensure_dir(working_dir)

    attachments = extract_email_attachments(
        email_message,
        working_dir,
        email_reference
    )

    # -------- Email fields (via shared extractors) --------

    from_addr = ec.extract_address(email_message.get("From"))
    to_addr = ec.extract_address(email_message.get("To"))
    cc_addr = ec.extract_address(email_message.get("Cc"))
    bcc_addr = ec.extract_address(email_message.get("Bcc"))

    subject = ec.decode_header_value(email_message.get("Subject", ""))
    email_text_parts = ec.extract_text_parts(email_message)
    headers = ec.extract_header_dict(email_message)

    logger.debug(f"Parsed From: {from_addr}")
    logger.debug(f"Parsed To: {to_addr}")
    logger.debug(f"Parsed Cc: {cc_addr}")
    logger.debug(f"Parsed Bcc: {bcc_addr}")

    # -------- Reporter logic (shared contract) --------

    to_addr, reporter = ec.resolve_reporter_and_to(to_addr, reported_by)

    # -------- Model creation --------

    email_data = EmailDataModel(
        reportedBy=reporter,
        **{
            "from": from_addr,
            "to": to_addr,
            "cc": cc_addr,
            "bcc": bcc_addr,
            "reportedSubject": subject,
            "reportedText": email_text_parts,
            "date": email_message.get("Date", ""),
            "headers": headers,
            "id": email_reference,
            "attachments": attachments,
        }
    )

    logger.debug(f"Processed email '{subject}' ({email_reference})")

    return email_data