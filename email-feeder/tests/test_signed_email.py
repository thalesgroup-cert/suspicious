"""
Regression tests for issue #77: email_feeder can't ingest S/MIME signed
emails. Standalone unittest (no pytest, no IMAP/network) so it runs with
just the feeder's own runtime dependencies via:
    cd email-feeder && python -m unittest tests.test_signed_email
"""
import email
import email.policy
import logging
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from classes.services.mailbox_service import Mailbox


def _mb():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _parse(raw: bytes) -> email.message.EmailMessage:
    return email.message_from_bytes(raw, policy=email.policy.default)


SIGNED_RAW = (
    b"From: a@b\r\nMIME-Version: 1.0\r\n"
    b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary=S\r\n\r\n'
    b"--S\r\nContent-Type: text/plain\r\n\r\nsigned body text\r\n"
    b"--S\r\nContent-Type: application/pkcs7-signature\r\n\r\nSIGBYTES\r\n--S--\r\n"
)

# The real-world shape from issue #77: a signed envelope wrapping a
# multipart/mixed body+attachment, plus the detached signature. Without
# unwrapping, iter_attachments() on the outer envelope treats the whole
# inner multipart/mixed as one nameless opaque attachment (surfaced in the
# bug report as "Attachment 'attachment_0.dat' has no decodable payload"),
# and the real attachment inside it is never extracted.
SIGNED_WITH_ATTACHMENT_RAW = (
    b"From: a@b\r\nMIME-Version: 1.0\r\n"
    b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary=S\r\n\r\n'
    b"--S\r\n"
    b"Content-Type: multipart/mixed; boundary=M\r\n\r\n"
    b"--M\r\nContent-Type: text/plain\r\n\r\nhello signed world\r\n"
    b'--M\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="real.bin"\r\n\r\n'
    b"ATTACHBYTES\r\n"
    b"--M--\r\n"
    b"--S\r\nContent-Type: application/pkcs7-signature\r\n\r\nSIGBYTES\r\n--S--\r\n"
)


class SignedEmailTests(unittest.TestCase):
    def test_unwrap_signed_returns_first_part(self):
        inner = _mb()._unwrap_signed(_parse(SIGNED_RAW))
        self.assertEqual(inner.get_content_type(), "text/plain")

    def test_unwrap_signed_passthrough_for_plain(self):
        msg = _parse(b"From: a@b\r\nContent-Type: text/plain\r\n\r\nx\r\n")
        self.assertIs(_mb()._unwrap_signed(msg), msg)

    def test_extract_body_unwraps_multipart_signed(self):
        plain, _ = _mb().extract_body(_parse(SIGNED_RAW))
        self.assertIn("signed body text", plain)
        self.assertNotEqual(plain, "Encrypted email")

    def test_unwrap_signed_surfaces_real_attachment(self):
        msg = _mb()._unwrap_signed(_parse(SIGNED_WITH_ATTACHMENT_RAW))
        filenames = [part.get_filename() for part in msg.iter_attachments()]
        self.assertEqual(filenames, ["real.bin"])


if __name__ == "__main__":
    unittest.main()
