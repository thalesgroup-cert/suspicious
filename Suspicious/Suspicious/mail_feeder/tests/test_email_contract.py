import email
import email.policy
import email.message
import hashlib

from django.test import TestCase
from mail_feeder import email_contract as ec


def _msg():
    m = email.message.EmailMessage()
    m["From"] = "Alice <ALICE@Example.TEST>"
    m["To"] = "bob@example.test"
    m["Subject"] = "Hello"
    m.set_content("plain body")
    m.add_attachment(b"PDFDATA", maintype="application", subtype="pdf",
                     filename="report.pdf")
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)


class EmailContractMirrorTests(TestCase):
    def test_build_metadata_matches_feeder_semantics(self):
        meta = ec.build_email_metadata(_msg(), "260625140959-aa")
        self.assertEqual(meta.from_, "alice@example.test")
        self.assertEqual(meta.attachments[0].sha256, hashlib.sha256(b"PDFDATA").hexdigest())
        self.assertTrue(ec.EmailMetadata.model_validate(meta.model_dump(by_alias=True)))
