import os
import tempfile
from email.message import EmailMessage
from unittest import TestCase
from unittest.mock import patch, mock_open

from pydantic import ValidationError

from mail_feeder.email_parser.parser import (
    parse_email,
    extract_email_attachments,
    get_header_dict_list,
)
from mail_feeder.email_parser.models import EmailDataModel, AttachmentModel


class EmailParserTests(TestCase):

    def _build_basic_email(self):
        msg = EmailMessage()
        msg["From"] = "Alice <alice@example.com>"
        msg["To"] = "soc@example.com"
        msg["Subject"] = "Test subject"
        msg["Date"] = "Mon, 1 Jan 2024 10:00:00 +0000"
        msg.set_content("Plain text body")
        return msg

    def test_parse_email_minimal_success(self):
        msg = self._build_basic_email()

        with tempfile.TemporaryDirectory() as tmpdir:
            data = parse_email(
                email_message=msg,
                working_dir=tmpdir,
                email_reference="ref-123",
            )

        self.assertIsInstance(data, EmailDataModel)
        self.assertEqual(data.reportedBy, "alice@example.com")
        self.assertEqual(data.from_addr, "alice@example.com")
        self.assertEqual(data.to, "soc@example.com")
        self.assertEqual(data.reportedSubject, "Test subject")
        self.assertEqual(len(data.reportedText), 1)
        self.assertIn("Plain text body", data.reportedText[0])
        self.assertEqual(data.attachments, [])

    def test_parse_email_with_reported_by_override(self):
        msg = self._build_basic_email()

        with tempfile.TemporaryDirectory() as tmpdir:
            data = parse_email(
                msg,
                tmpdir,
                "ref-override",
                reported_by="override@example.com",
            )

        self.assertEqual(data.reportedBy, "override@example.com")

    def test_invalid_email_fails_validation(self):
        msg = self._build_basic_email()
        msg.replace_header("From", "not-an-email")

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValidationError):
                parse_email(msg, tmpdir, "ref-invalid")

    def test_header_dict_decoding(self):
        msg = self._build_basic_email()
        headers = get_header_dict_list(msg)

        self.assertIn("From", headers)
        self.assertEqual(headers["From"], "Alice <alice@example.com>")

    @patch("builtins.open", new_callable=mock_open)
    def test_extract_single_attachment(self, mock_file):
        msg = self._build_basic_email()

        attachment = EmailMessage()
        attachment.set_content(b"binarydata", maintype="application", subtype="octet-stream")
        attachment.add_header("Content-Disposition", "attachment", filename="file.bin")
        msg.make_mixed()
        msg.attach(attachment)

        with tempfile.TemporaryDirectory() as tmpdir:
            attachments = extract_email_attachments(
                email_message=msg,
                save_dir=tmpdir,
                email_reference="ref-att",
            )

        self.assertEqual(len(attachments), 1)
        att = attachments[0]
        self.assertIsInstance(att, AttachmentModel)
        self.assertEqual(att.filename, "file.bin")
        self.assertEqual(att.content, b"binarydata")
        self.assertEqual(att.parent, "ref-att")

    @patch("builtins.open", side_effect=IOError("disk full"))
    def test_attachment_write_failure_is_ignored(self, mock_file):
        msg = self._build_basic_email()

        attachment = EmailMessage()
        attachment.set_content(b"data", maintype="application", subtype="octet-stream")
        attachment.add_header("Content-Disposition", "attachment", filename="fail.bin")
        msg.make_mixed()
        msg.attach(attachment)

        with tempfile.TemporaryDirectory() as tmpdir:
            attachments = extract_email_attachments(
                msg,
                tmpdir,
                "ref-fail",
            )

        self.assertEqual(attachments, [])
