import os
import logging
import uuid
from datetime import datetime
from email.header import decode_header, make_header
from email.utils import parseaddr
from email.message import Message
from typing import Optional, List, Dict, Any


def parse_email(email_message: Message, working_dir: str, email_reference: str, reported_by: Optional[str] = None) -> Dict[str, Any]:
    """
    Parse an email message, extract key information and attachments, and return as a dictionary.

    Args:
        email_message (Message): The email message object to process.
        working_dir (str): Directory where attachments will be saved.
        email_reference (str): Unique reference for this email.
        reported_by (Optional[str]): Email address of the reporter, if different from 'From' header.

    Returns:
        Dict[str, Any]: Parsed email data including headers, text, attachments, and metadata.
    """
    try:
        os.makedirs(working_dir, exist_ok=True)
        attachments = extract_email_attachments(email_message, working_dir, email_reference)

        from_addr = decode_email_header(parseaddr(email_message.get('From', ''))[1])
        to_addr = decode_email_header(parseaddr(email_message.get('To', ''))[1])
        cc_addr = decode_email_header(parseaddr(email_message.get('Cc', ''))[1])
        bcc_addr = decode_email_header(parseaddr(email_message.get('Bcc', ''))[1])
        subject = decode_email_header(email_message.get('Subject', ''))

        reporter = reported_by if reported_by else from_addr

        email_text_parts = [
            part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
            for part in email_message.walk()
            if part.get_content_type() in ['text/plain', 'text/html']
        ]

        email_info = {
            'reportedBy': reporter,
            'from': from_addr,
            'to': to_addr,
            'cc': cc_addr,
            'bcc': bcc_addr,
            'reportedSubject': subject,
            'reportedText': email_text_parts,
            'date': email_message.get('Date', ''),
            'headers': get_header_dict_list(email_message),
            'id': email_reference,
            'attachments': attachments
        }

        logging.debug(f"Processed email '{subject}' with reference {email_reference}")

        return email_info
    except Exception as e:
        logging.error(f"Failed to parse email: {e}")
        return None


def extract_email_attachments(email_message: Message, save_dir: str, email_reference: str) -> List[Dict[str, Any]]:
    """
    Extract attachments from an email message and save them in the given directory.

    Args:
        email_message (Message): Email message object.
        save_dir (str): Directory path to save attachments.
        email_reference (str): Reference ID for the parent email.

    Returns:
        List[Dict[str, Any]]: List of dictionaries representing attachments with metadata.
    """
    attachments = []

    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        content_disposition = part.get('Content-Disposition', '')
        if not content_disposition or 'attachment' not in content_disposition.lower():
            continue

        raw_filename = part.get_filename()
        if raw_filename:
            decoded_filename = decode_email_header(raw_filename)
            filepath = os.path.join(save_dir, decoded_filename)

            try:
                with open(filepath, "wb") as f:
                    f.write(part.get_payload(decode=True))
            except Exception as e:
                logging.error(f"Failed to save attachment {decoded_filename}: {e}")
                continue

            attachment_data = {
                'filename': decoded_filename,
                'content': part.get_payload(decode=True),
                'headers': dict(part.items()),
                'parent': email_reference
            }
            attachments.append(attachment_data)

    return attachments


def decode_email_header(header_value: str) -> str:
    """
    Decode an encoded email header to a readable string.

    Args:
        header_value (str): The encoded header string.

    Returns:
        str: Decoded header string.
    """
    try:
        decoded_header = str(make_header(decode_header(header_value)))
        return decoded_header
    except Exception as e:
        logging.error(f"Failed to decode header '{header_value}': {e}")
        return header_value


def generate_unique_email_reference() -> str:
    """
    Generate a unique reference string for emails.

    Returns:
        str: Unique reference string formatted as YYMMDDHHMMSS-12hexchars
    """
    now = datetime.now()
    ref_date = now.strftime("%y%m%d%H%M%S")
    formatted_uuid = uuid.uuid4().hex[:12]
    return f"{ref_date}-{formatted_uuid}"


def get_header_dict_list(email_message: Message) -> Dict[str, str]:
    """
    Convert email headers into a dictionary.

    Args:
        email_message (Message): The email message object.

    Returns:
        Dict[str, str]: Dictionary of header names and their values.
    """
    return {k: decode_email_header(v) for k, v in email_message.items()}
