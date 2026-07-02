"""Outlook .msg handling: detection flag + conversion to EmailMessage.

The classification matrix proves a .msg submission is now detected as valid
(is_email). These tests cover the two mechanics behind the fix: the `is_msg`
flag set during extraction, and `_convert_msg_to_email` delegating to
extract-msg (mocked — no real OLE fixture needed).
"""
import email
import email.policy
import logging
import pathlib
import tempfile
from unittest import mock

from classes.services.mailbox_service import Mailbox


def _mailbox():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def test_extract_sets_is_msg_for_outlook_attachment():
    raw = (
        b"From: user@corp.com\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
        b"--B\r\nContent-Type: application/vnd.ms-outlook\r\n"
        b'Content-Disposition: attachment; filename="message.msg"\r\n\r\n'
        b"OLE-COMPOUND-BYTES\r\n--B--\r\n"
    )
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    with tempfile.TemporaryDirectory() as d:
        atts = _mailbox().extract_attachments(msg, pathlib.Path(d), "ref")
    msg_atts = [a for a in atts if a.is_msg]
    assert msg_atts, "Outlook .msg attachment must be flagged is_msg"
    assert msg_atts[0].is_email, "a .msg is also an attached email (valid submission)"


def test_convert_msg_to_email_delegates_to_extract_msg(tmp_path, monkeypatch):
    inner = email.message_from_bytes(
        b"From: attacker@evil.test\r\nSubject: phish\r\n\r\nbody",
        policy=email.policy.default,
    )
    fake = mock.Mock()
    fake.asEmailMessage.return_value = inner

    import extract_msg

    monkeypatch.setattr(extract_msg, "openMsg", lambda p: fake)

    msg_path = tmp_path / "m.msg"
    msg_path.write_bytes(b"OLE")

    out = _mailbox()._convert_msg_to_email(msg_path)

    assert out is inner
    fake.asEmailMessage.assert_called_once()
    fake.close.assert_called_once()  # handle always closed
