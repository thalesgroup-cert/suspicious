"""Classification matrix for forwarded-submission detection.

This is the regression net for THE production bug: some users forward a genuine
suspicious email (so the submission is VALID and must be analysed), but the
feeder classified it NO_ATTACHED_MAIL and sent the bad-submission ack.

Each case runs the REAL `Mailbox.extract_attachments` over a realistic
multipart message produced by a given mail client, and asserts whether any
extracted part is detected as an attached email (`is_email`) — which is exactly
what `process_inbox_email` keys the VALID vs NO_ATTACHED_MAIL decision on.

Root cause captured here: Outlook desktop "Forward as Attachment" produces a
`.msg` (application/vnd.ms-outlook), which the `.eml`/rfc822-only detection
misses. Those cases are xfail until `.msg` support lands; remove the xfail when
it does.
"""
import email
import email.policy
import logging
import pathlib
import tempfile

from classes.services.mailbox_service import Mailbox


def _mailbox():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _detects_attached_email(raw: bytes) -> bool:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    mb = _mailbox()
    with tempfile.TemporaryDirectory() as d:
        atts = mb.extract_attachments(msg, pathlib.Path(d), "ref-1")
    return any(a.is_email for a in atts)


_INNER = (
    b"From: attacker@evil.test\r\nSubject: phish\r\n"
    b"Content-Type: text/plain\r\n\r\nclick this link\r\n"
)


def _wrap(disposition: str, ctype: str, filename: str, body_first: bool = True) -> bytes:
    parts = [
        b"From: user@corp.com\r\nSubject: Fwd: suspicious\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=B\r\n\r\n"
    ]
    if body_first:
        parts.append(b"--B\r\nContent-Type: text/plain\r\n\r\nPlease analyse this.\r\n")
    fn = f'; filename="{filename}"' if filename else ""
    parts.append(
        f"--B\r\nContent-Type: {ctype}\r\nContent-Disposition: {disposition}{fn}\r\n\r\n".encode()
    )
    parts.append(_INNER)
    parts.append(b"\r\n--B--\r\n")
    return b"".join(parts)


# --- VALID submissions: a genuine email is attached, must be detected ---------

def test_gmail_rfc822_attachment_with_eml_name():
    assert _detects_attached_email(_wrap("attachment", "message/rfc822", "forwarded.eml"))


def test_rfc822_attachment_without_filename():
    assert _detects_attached_email(_wrap("attachment", "message/rfc822", ""))


def test_rfc822_inline_disposition():
    # Some clients mark the attached message inline; still a valid submission.
    assert _detects_attached_email(_wrap("inline", "message/rfc822", "forwarded.eml"))


def test_rfc822_no_disposition_header():
    raw = (
        b"From: user@corp.com\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
        b"--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        b"--B\r\nContent-Type: message/rfc822\r\n\r\n" + _INNER + b"\r\n--B--\r\n"
    )
    assert _detects_attached_email(raw)


def test_eml_as_octet_stream_by_extension():
    assert _detects_attached_email(
        _wrap("attachment", "application/octet-stream", "suspicious.eml")
    )


def test_outlook_msg_vnd_mime_type():
    # Outlook desktop "Forward as Attachment" -> application/vnd.ms-outlook, *.msg
    assert _detects_attached_email(
        _wrap("attachment", "application/vnd.ms-outlook", "message.msg")
    )


def test_outlook_msg_as_octet_stream():
    assert _detects_attached_email(
        _wrap("attachment", "application/octet-stream", "message.msg")
    )


# --- Genuinely BAD submissions: no attached email, bad-ack is correct ---------

def test_plain_text_no_attachment_is_bad():
    raw = b"From: user@corp.com\r\nContent-Type: text/plain\r\n\r\njust text, no attachment\r\n"
    assert not _detects_attached_email(raw)


def test_pdf_only_attachment_is_bad():
    raw = _wrap("attachment", "application/pdf", "invoice.pdf")
    assert not _detects_attached_email(raw)
