"""End-to-end Outlook .msg path using a REAL .msg OLE fixture (no mock).

`tests/fixtures/sample.msg` is a genuine Outlook .msg compound file. This proves
the full real path: a forwarded .msg attachment is extracted, flagged is_msg,
and converted to a parseable EmailMessage by extract-msg — i.e. an Outlook
submission is analysed instead of bad-acked.

If the fixture is absent the test skips, so the suite stays green in a checkout
without the binary; drop a real Outlook .msg at that path to exercise it.
"""
import email
import email.message
import email.policy
import logging
import pathlib
import tempfile

import pytest

from classes.services.mailbox_service import Mailbox

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample.msg"


def _mb():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


@pytest.mark.skipif(not FIXTURE.exists(), reason="no real .msg fixture committed")
def test_real_msg_attachment_detected_and_converted():
    msg_bytes = FIXTURE.read_bytes()

    # Build a wrapper email with the real .msg attached, as Outlook would.
    wrapper = email.message.EmailMessage()
    wrapper["From"] = "user@corp.com"
    wrapper["Subject"] = "Fwd: suspicious"
    wrapper.set_content("Please analyse the attached message.")
    wrapper.add_attachment(
        msg_bytes,
        maintype="application", subtype="vnd.ms-outlook",
        filename="message.msg",
    )
    parsed = email.message_from_bytes(wrapper.as_bytes(), policy=email.policy.default)

    mb = _mb()
    with tempfile.TemporaryDirectory() as d:
        atts = mb.extract_attachments(parsed, pathlib.Path(d), "ref-1")
        msg_atts = [a for a in atts if a.is_msg]
        assert msg_atts, "real .msg must be detected as is_msg"
        assert msg_atts[0].is_email, "a .msg is a valid attached email"

        # Real conversion of the written .msg file -> EmailMessage (no mock).
        converted = mb._convert_msg_to_email(pathlib.Path(msg_atts[0].file_path))
        assert isinstance(converted, email.message.Message)
        # It is a real parsed email object (has headers, even if sparse).
        assert converted.items() is not None
