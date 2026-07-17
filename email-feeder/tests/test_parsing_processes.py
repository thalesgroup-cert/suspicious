"""Characterization tests for the feeder's email-parsing processes.

These lock the CURRENT behavior of the proven parsing helpers so the
modernization work (and future edits) cannot regress them. They exercise the
real methods on a Mailbox built without an IMAP client.
"""
import email
import email.policy
import hashlib
import logging
import pathlib
import tempfile

from classes.services.mailbox_service import Mailbox


def _mb():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _parse(raw: bytes) -> email.message.EmailMessage:
    return email.message_from_bytes(raw, policy=email.policy.default)


# --- extract_body ------------------------------------------------------------

def test_extract_body_plain_only():
    msg = _parse(b"From: a@b\r\nContent-Type: text/plain\r\n\r\nhello world\r\n")
    plain, html = _mb().extract_body(msg)
    assert "hello world" in plain
    # html falls back to the plain text when absent
    assert "hello world" in html


def test_extract_body_html_only_derives_plain():
    msg = _parse(
        b"From: a@b\r\nContent-Type: text/html\r\n\r\n<p>Click <b>here</b></p>\r\n"
    )
    plain, html = _mb().extract_body(msg)
    assert "Click" in plain and "<p>" not in plain  # stripped to text
    assert "<p>" in html


def test_extract_body_encrypted_placeholder():
    msg = _parse(
        b"From: a@b\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\n"
        b"BASE64ENCRYPTEDBLOB\r\n"
    )
    plain, html = _mb().extract_body(msg)
    assert plain == "Encrypted email"
    assert html == "Encrypted email"


def test_extract_body_unwraps_multipart_signed():
    raw = (
        b"From: a@b\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=S\r\n\r\n"
        b"--S\r\nContent-Type: text/plain\r\n\r\nsigned body text\r\n"
        b"--S\r\nContent-Type: application/pkcs7-signature\r\n\r\nSIGBYTES\r\n--S--\r\n"
    )
    plain, _ = _mb().extract_body(_parse(raw))
    assert "signed body text" in plain


# --- _unwrap_signed ----------------------------------------------------------

def test_unwrap_signed_returns_first_part():
    raw = (
        b"From: a@b\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=S\r\n\r\n"
        b"--S\r\nContent-Type: text/plain\r\n\r\ninner\r\n"
        b"--S\r\nContent-Type: application/pkcs7-signature\r\n\r\nSIG\r\n--S--\r\n"
    )
    inner = _mb()._unwrap_signed(_parse(raw))
    assert inner.get_content_type() == "text/plain"


def test_unwrap_signed_passthrough_for_plain():
    msg = _parse(b"From: a@b\r\nContent-Type: text/plain\r\n\r\nx\r\n")
    assert _mb()._unwrap_signed(msg) is msg


# --- header field processors -------------------------------------------------

def test_process_recipients_field_splits_addresses():
    out = _mb().process_recipients_field("Alice <a@x.com>, b@y.com")
    assert out == ["a@x.com", "b@y.com"]


def test_process_recipients_field_empty():
    assert _mb().process_recipients_field(None) == []


def test_process_subject_field_plain_strips_newlines():
    assert _mb().process_subject_field("Hello\r\nthere") == "Hellothere"


def test_process_subject_field_rfc2047():
    # =?UTF-8?B?w6k=?= decodes to "é"
    assert _mb().process_subject_field("=?UTF-8?B?w6k=?=") == "é"


def test_process_date_field_valid():
    out = _mb().process_date_field("Mon, 26 Mar 2026 14:11:59 +0000")
    assert out and "2026" in out


def test_process_date_field_invalid_returns_none():
    assert _mb().process_date_field("not a date") is None


# --- body cleanup + hashing --------------------------------------------------

def test_process_body_strips_nbsp_and_classification():
    raw = "Hello world\nSensitivity: High\n[cid:logo.png]\nbye"
    out = _mb().process_body(raw)
    assert " " not in out
    assert "Sensitivity:" not in out
    assert "cid:" not in out
    assert "Hello" in out and "bye" in out


def test_get_sha256_matches_hashlib():
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "f.bin"
        p.write_bytes(b"abc123")
        assert _mb().get_sha256(p) == hashlib.sha256(b"abc123").hexdigest()


def test_get_sha256_missing_file_returns_none():
    assert _mb().get_sha256(pathlib.Path("/no/such/file")) is None
