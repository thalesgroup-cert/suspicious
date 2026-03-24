import os
import logging
from email.message import Message
from email.utils import getaddresses
from typing import List, Dict, Optional

from .utils import decode_email_header, ensure_dir
from .models import EmailDataModel, AttachmentModel

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


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

        decoded_filename = decode_email_header(raw_filename)
        filepath = os.path.join(save_dir, decoded_filename)

        try:
            payload = part.get_payload(decode=True)

            with open(filepath, "wb") as f:
                f.write(payload)

            attachments.append(
                AttachmentModel(
                    filename=decoded_filename,
                    content=payload,
                    headers=dict(part.items()),
                    parent=email_reference
                )
            )

        except Exception as e:
            logger.error(f"Failed to save attachment {decoded_filename}: {e}")

    return attachments


# -------------------------
# Headers
# -------------------------

def get_header_dict_list(email_message: Message) -> Dict[str, str]:
    return {
        k: decode_email_header(v)
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

    # -------- Email fields --------

    from_addr = decode_and_extract(email_message.get("From"))
    to_addr = decode_and_extract(email_message.get("To"))
    cc_addr = decode_and_extract(email_message.get("Cc"))
    bcc_addr = decode_and_extract(email_message.get("Bcc"))

    subject = decode_email_header(email_message.get("Subject", ""))

    logger.debug(f"Parsed From: {from_addr}")
    logger.debug(f"Parsed To: {to_addr}")
    logger.debug(f"Parsed Cc: {cc_addr}")
    logger.debug(f"Parsed Bcc: {bcc_addr}")

    # -------- Reporter logic (critical) --------

    reporter = reported_by if reported_by else to_addr
    if to_addr == "" or to_addr == "Undisclosed recipients:;"or not to_addr:
        to_addr = "no.recipient@noemail.com"
    if not reporter:
        logger.warning("No valid reporter email found")
        reporter = to_addr

    # -------- Body extraction --------

    email_text_parts: List[str] = []

    for part in email_message.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode(
                        part.get_content_charset("utf-8"),
                        errors="replace"
                    )
                    email_text_parts.append(text)
            except Exception as e:
                logger.warning(f"Failed to decode email part: {e}")

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
            "headers": get_header_dict_list(email_message),
            "id": email_reference,
            "attachments": attachments
        }
    )

    logger.debug(f"Processed email '{subject}' ({email_reference})")

    return email_data