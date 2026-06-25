import hashlib
import os
import tempfile
from django.test import TestCase

from mail_feeder import email_contract as ec
from mail_feeder.email_parser.from_metadata import (
    build_email_data_model, MetadataIntegrityError,
)


def _meta(att_sha):
    return ec.EmailMetadata.model_validate({
        "schema": 1, "id": "260625140959-aa", "from": "att@evil.test",
        "to": "victim@corp.test", "cc": None, "bcc": None,
        "reportedSubject": "phish", "reportedText": ["click here"],
        "date": "Mon, 1 Jan 2026 00:00:00 +0000", "headers": {"From": "att@evil.test"},
        "attachments": [{"filename": "p.pdf", "sha256": att_sha, "headers": {"X": "y"}}],
    })


class BuildEmailDataModelTests(TestCase):
    def test_hydrates_and_maps(self):
        with tempfile.TemporaryDirectory() as d:
            payload = b"PDF"
            with open(os.path.join(d, "p.pdf"), "wb") as f:
                f.write(payload)
            meta = _meta(hashlib.sha256(payload).hexdigest())
            model = build_email_data_model(meta, "reporter@corp.test", d)
            self.assertEqual(model.reportedBy, "reporter@corp.test")
            self.assertEqual(model.from_addr, "att@evil.test")
            self.assertEqual(model.to, "victim@corp.test")
            self.assertEqual(model.reportedText, ["click here"])
            self.assertEqual(model.attachments[0].content, payload)
            self.assertEqual(model.attachments[0].parent, "260625140959-aa")

    def test_sha_mismatch_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "p.pdf"), "wb") as f:
                f.write(b"TAMPERED")
            meta = _meta(hashlib.sha256(b"PDF").hexdigest())
            with self.assertRaises(MetadataIntegrityError):
                build_email_data_model(meta, "reporter@corp.test", d)

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as d:
            meta = _meta(hashlib.sha256(b"PDF").hexdigest())
            with self.assertRaises(MetadataIntegrityError):
                build_email_data_model(meta, "reporter@corp.test", d)

    def test_empty_to_defaulted_and_reporter_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            meta = ec.EmailMetadata.model_validate({
                "schema": 1, "id": "x-1", "from": "a@b.test", "to": None,
                "reportedSubject": "s", "reportedText": [], "date": "",
                "headers": {}, "attachments": [],
            })
            model = build_email_data_model(meta, "", d)
            self.assertEqual(model.to, "no.recipient@noemail.com")
            self.assertEqual(model.reportedBy, "no.recipient@noemail.com")
