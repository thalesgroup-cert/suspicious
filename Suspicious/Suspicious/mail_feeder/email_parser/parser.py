import os
import logging
from email.message import Message
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

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


def extract_email_attachments(
    email_message: Message,
    save_dir: str,
    email_reference: str
) -> List[AttachmentModel]:
    """
    Extract attachments from an email message and save them to disk.
    """
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

        decoded_filename = decode_email_header(raw_filename)
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
                    headers=dict(part.items()),
                    parent=email_reference
                )
            )
        except Exception as e:
            logger.error(f"Failed to save attachment {safe_filename}: {e}")

    return attachments


def get_header_dict_list(email_message: Message) -> Dict[str, str]:
    """
    Convert email headers into a dictionary.
    """
    return {k: decode_email_header(v) for k, v in email_message.items()}


def parse_email(
    email_message: Message,
    working_dir: str,
    email_reference: str,
    reported_by: Optional[str] = None
) -> EmailDataModel:
    """
    Parse an email message and return structured data including headers, text, attachments, and metadata.
    """
    ensure_dir(working_dir)
    attachments = extract_email_attachments(email_message, working_dir, email_reference)

    from_addr = decode_email_header(email_message.get("From", ""))
    logger.debug(f"Decoded From address: {from_addr}")
    to_addr = decode_email_header(email_message.get("To", ""))
    logger.debug(f"Decoded To address: {to_addr}")
    cc_addr = decode_email_header(email_message.get("Cc", ""))
    logger.debug(f"Decoded Cc address: {cc_addr}")
    bcc_addr = decode_email_header(email_message.get("Bcc", ""))
    logger.debug(f"Decoded Bcc address: {bcc_addr}")
    subject = decode_email_header(email_message.get("Subject", ""))
    logger.debug(f"Decoded Subject: {subject}")
    reporter = reported_by or to_addr
    logger.debug(f"Using reporter: {reporter}")

    email_text_parts = [
        part.get_payload(decode=True).decode(part.get_content_charset("utf-8"), errors="replace")
        for part in email_message.walk()
        if part.get_content_type() in ["text/plain", "text/html"]
    ]

    email_data = EmailDataModel(
        reportedBy=reporter,
        **{
            "mail_from": from_addr,
            "from": from_addr,
            "to": to_addr,
            "cc": cc_addr,
            "bcc": bcc_addr,
            "reportedSubject": subject,
            "reportedText": email_text_parts,
            "date": email_message.get("Date", ""),
            "headers": get_header_dict_list(email_message),
            "id": email_reference,
            "attachments": attachments
        }
    )

    logger.debug(f"Processed email '{subject}' with reference {email_reference}")
    return email_data
