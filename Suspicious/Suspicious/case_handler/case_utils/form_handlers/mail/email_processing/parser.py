# email_processing/parser.py
import re
import logging
import mimetypes
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from email.message import EmailMessage
from email.parser import HeaderParser
from email.utils import parseaddr
import chardet
from bs4 import BeautifulSoup
from dateutil import parser as dt_parser, tz

from case_handler.case_utils.form_handlers.mail.email_processing.utils import (
    decode_header_str,
    sanitize_filename,
    get_sha256,
    header_dict_list,
)

logger = logging.getLogger(__name__)

class EmailParser:
    """
    Parses EmailMessage to extract headers, recipients, date, subject, body, and attachments.
    """

    def __init__(self, tmp_dir: Path, source_ref: str):
        self.tmp_dir = tmp_dir
        self.source_ref = source_ref
        self.attachments_dir = tmp_dir / "attachments"
        self.attachments_dir.mkdir(parents=True, exist_ok=True)

    def parse(self, msg: EmailMessage) -> Dict:
        data = {
            "to": self._process_recipients(msg.get("To")),
            "cc": self._process_recipients(msg.get("Cc")),
            "bcc": self._process_recipients(msg.get("Bcc")),
            "date": self._process_date(msg.get("Date")),
            "subject": self._process_subject(decode_header_str(msg.get("Subject"))),
            "from_address": self._process_from(msg.get("From")),
            "attachments": self._extract_attachments(msg),
        }

        # Body
        plain, html = self._extract_body(msg)
        data["body_text"] = self._clean_body(plain)
        data["body_html"] = html

        # Headers parsing
        data["headers_parsed"] = self._extract_headers(msg)

        data["raw_eml_bytes"] = msg.as_bytes()
        return data

    def _process_recipients(self, raw: Optional[str]) -> List[str]:
        if not raw:
            return []
        return [addr for _, addr in EmailMessage().get_all("To", [])]  # import fix: uses email.utils

    def _process_subject(self, raw: Optional[str]) -> Optional[str]:
        if raw is None:
            return None
        clean = raw.replace("\r", "").replace("\n", "")
        return clean

    def _process_date(self, raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        try:
            dt = dt_parser.parse(raw).astimezone(tz.gettz("Europe/Paris"))
            return dt.strftime("%A %-d %B %Y %H:%M:%S")
        except Exception as e:
            logger.error("Invalid date '%s': %s", raw, e)
            return None

    def _process_from(self, raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        decoded = decode_header_str(raw)
        return parseaddr(decoded)[1]

    def _extract_body(self, msg: EmailMessage) -> Tuple[str, str]:
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))

        def get_content(part):
            if not part:
                return None
            payload = part.get_payload(decode=True)
            return payload if payload else part.get_payload()

        raw_plain = get_content(plain_part)
        raw_html = get_content(html_part)

        def to_str(raw):
            if raw is None:
                return None
            if isinstance(raw, (bytes, bytearray)):
                enc = chardet.detect(raw)["encoding"] or "utf-8"
                try:
                    return raw.decode(enc)
                except:
                    return raw.decode("utf-8", errors="replace")
            return raw

        plain = to_str(raw_plain)
        html = to_str(raw_html)

        if not plain and html:
            plain = BeautifulSoup(html, "html.parser").get_text()
        if not html and plain:
            html = plain

        if msg.get_content_type() in ("application/pkcs7-mime", "multipart/encrypted") or (plain is None and html is None):
            return "Encrypted email", "Encrypted email"

        return plain or "", html or ""

    def _clean_body(self, text: Optional[str]) -> str:
        if not text:
            return ""
        patterns = [
            (r"\u00A0|\r", ""),
            (r" +\n", "\n"),
            (r"=\n", ""),
            (r"\n{3,}", "\n\n"),
            (r"^\s+|\s+$", ""),
        ]
        for pat, repl in patterns:
            text = re.sub(pat, repl, text, flags=re.MULTILINE)
        return text

    def _extract_headers(self, msg: EmailMessage):
        raw = msg.as_bytes()
        sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
        try:
            block = raw.split(sep, 1)[0].decode("ascii", "replace")
            return HeaderParser().parsestr(block)
        except Exception:
            return {k: decode_header_str(v) for k, v in msg.items()}

    def _extract_attachments(self, msg: EmailMessage) -> List[Dict]:
        results = []
        for i, part in enumerate(msg.iter_attachments()):
            filename = part.get_filename()
            ctype = part.get_content_type()

            if filename:
                name = sanitize_filename(decode_header_str(filename), i)
            elif ctype == "message/rfc822":
                name = sanitize_filename("embedded_email", i) + ".eml"
            else:
                ext = mimetypes.guess_extension(ctype) or ".bin"
                name = sanitize_filename(f"attachment_{i}", i) + ext

            path = self.attachments_dir / name
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = part.as_bytes()
            path.write_bytes(payload)
            results.append({
                "filename": name,
                "file_path": str(path),
                "file_sha256": get_sha256(str(path)),
                "headers": header_dict_list(part),
                "parent": self.source_ref,
            })
        return results
