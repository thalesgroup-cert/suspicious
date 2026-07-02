# Suspicious/Suspicious/mail_feeder/global_submission/tests_ingest_parity.py
# REGRESSION GUARD (characterization), not red-green TDD: Tasks 4-5 already
# enforce fast==fallback parity, so this may pass on first run. Its value is
# catching future divergence at the integration seam (load_email_data).
import email
import email.message
import email.policy
import json
import os
import tempfile
from unittest.mock import patch
from django.test import TestCase

from mail_feeder import email_contract as ec
from mail_feeder.global_submission.fast_metadata import load_email_data


def _build(d):
    inner = email.message.EmailMessage()
    inner["From"] = "Att <ATT@Evil.TEST>"
    inner["To"] = "victim@corp.test"
    inner["Subject"] = "=?utf-8?q?Cl=C3=ADck?="
    inner["Date"] = "Mon, 1 Jan 2026 00:00:00 +0000"
    inner.set_content("plain http://phish.test")
    inner.add_alternative("<p>html</p>", subtype="html")
    inner.add_attachment(b"PAYLOAD", maintype="application", subtype="pdf",
                         filename="inv.pdf")
    with open(os.path.join(d, "mail.eml"), "wb") as f:
        f.write(inner.as_bytes())
    return inner


class IngestParityTests(TestCase):
    def test_fast_and_fallback_produce_identical_model(self):
        with tempfile.TemporaryDirectory() as d:
            inner = _build(d)
            # fallback (flag off)
            with patch("mail_feeder.global_submission.fast_metadata."
                       "fast_metadata_enabled", return_value=False):
                fb = load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test")
            # write email.json + attachment + run fast (flag on)
            msg = email.message_from_bytes(inner.as_bytes(), policy=email.policy.default)
            meta = ec.build_email_metadata(msg, "260625140959-aa")
            with open(os.path.join(d, ec.EMAIL_METADATA_OBJECT_NAME), "w") as f:
                f.write(json.dumps(meta.model_dump(by_alias=True)))
            # place the attachment under attachments/ for the fast-path mapper
            os.makedirs(os.path.join(d, "attachments"), exist_ok=True)
            with open(os.path.join(d, "attachments", "inv.pdf"), "wb") as f:
                f.write(b"PAYLOAD")
            with patch("mail_feeder.global_submission.fast_metadata."
                       "fast_metadata_enabled", return_value=True):
                fa = load_email_data(d, "mail.eml", "260625140959-aa", "rep@corp.test")
            self.assertEqual(fa.model_dump(by_alias=True), fb.model_dump(by_alias=True))
