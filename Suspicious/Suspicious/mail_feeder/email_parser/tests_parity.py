import email
import email.message
import email.policy
import tempfile
from django.test import TestCase

from mail_feeder import email_contract as ec
from mail_feeder.email_parser.parser import parse_email
from mail_feeder.email_parser.from_metadata import build_email_data_model


def _fixture():
    inner = email.message.EmailMessage()
    inner["From"] = "Attacker <ATT@Evil.TEST>"
    inner["To"] = "victim@corp.test"
    inner["Cc"] = "cc@corp.test"
    inner["Subject"] = "=?utf-8?q?Cl=C3=ADck?="
    inner["Date"] = "Mon, 1 Jan 2026 00:00:00 +0000"
    inner.set_content("plain body http://phish.test")
    inner.add_alternative("<p>html body</p>", subtype="html")
    inner.add_attachment(b"PAYLOAD", maintype="application", subtype="pdf",
                         filename="invoice.pdf")
    return email.message_from_bytes(inner.as_bytes(), policy=email.policy.default)


class ParityTests(TestCase):
    def test_fast_path_equals_parse_email(self):
        msg = _fixture()
        with tempfile.TemporaryDirectory() as d:
            fallback = parse_email(msg, d, "260625140959-aa", "reporter@corp.test")
            # fast path: metadata derived from the same msg, attachments on disk
            # are exactly what parse_email just wrote into d.
            meta = ec.build_email_metadata(msg, "260625140959-aa")
            fast = build_email_data_model(meta, "reporter@corp.test", d)

        self.assertEqual(fast.model_dump(by_alias=True),
                         fallback.model_dump(by_alias=True))
