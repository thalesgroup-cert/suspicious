import email
import email.message
import email.policy
import json
import os
import tempfile
import email
import email.message
import email.policy
from unittest.mock import patch
from django.test import TestCase

from mail_feeder import email_contract as ec
from mail_feeder.global_submission.fast_metadata import load_email_data


def _write_submission(d):
    inner = email.message.EmailMessage()
    inner["From"] = "att@evil.test"
    inner["To"] = "victim@corp.test"
    inner["Subject"] = "phish"
    inner.set_content("click")
    inner.add_attachment(b"PAY", maintype="application", subtype="pdf",
                         filename="p.pdf")
    msg = email.message_from_bytes(inner.as_bytes(), policy=email.policy.default)
    with open(os.path.join(d, "mail.eml"), "wb") as f:
        f.write(inner.as_bytes())
    # Attachments live under <email-dir>/attachments/ — the layout the feeder
    # writes and build_email_data_model reads.
    os.makedirs(os.path.join(d, "attachments"), exist_ok=True)
    with open(os.path.join(d, "attachments", "p.pdf"), "wb") as f:
        f.write(b"PAY")
    meta = ec.build_email_metadata(msg, "260625140959-aa")
    with open(os.path.join(d, ec.EMAIL_METADATA_OBJECT_NAME), "w") as f:
        f.write(json.dumps(meta.model_dump(by_alias=True)))


class FastMetadataTests(TestCase):
    @patch("mail_feeder.global_submission.fast_metadata.fast_metadata_enabled", return_value=True)
    def test_fast_path_used_when_valid(self, _):
        with tempfile.TemporaryDirectory() as d:
            _write_submission(d)
            with patch("mail_feeder.global_submission.fast_metadata.parse_email") as pe:
                model = load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test")
                pe.assert_not_called()
            self.assertEqual(model.reportedBy, "rep@corp.test")
            self.assertEqual(model.from_addr, "att@evil.test")

    @patch("mail_feeder.global_submission.fast_metadata.fast_metadata_enabled", return_value=True)
    def test_falls_back_on_sha_mismatch(self, _):
        with tempfile.TemporaryDirectory() as d:
            _write_submission(d)
            with open(os.path.join(d, "attachments", "p.pdf"), "wb") as f:
                f.write(b"TAMPERED")
            with patch("mail_feeder.global_submission.fast_metadata.parse_email") as pe:
                pe.return_value = "FELL_BACK"
                result = load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test")
                pe.assert_called_once()
                self.assertEqual(result, "FELL_BACK")

    @patch("mail_feeder.global_submission.fast_metadata.fast_metadata_enabled", return_value=True)
    def test_falls_back_when_no_email_json(self, _):
        with tempfile.TemporaryDirectory() as d:
            _write_submission(d)
            os.remove(os.path.join(d, ec.EMAIL_METADATA_OBJECT_NAME))
            with patch("mail_feeder.global_submission.fast_metadata.parse_email") as pe:
                pe.return_value = "FELL_BACK"
                self.assertEqual(
                    load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test"),
                    "FELL_BACK")

    @patch("mail_feeder.global_submission.fast_metadata.fast_metadata_enabled", return_value=False)
    def test_flag_off_always_parses(self, _):
        with tempfile.TemporaryDirectory() as d:
            _write_submission(d)
            with patch("mail_feeder.global_submission.fast_metadata.parse_email") as pe:
                pe.return_value = "FELL_BACK"
                self.assertEqual(
                    load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test"),
                    "FELL_BACK")
