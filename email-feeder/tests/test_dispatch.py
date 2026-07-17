"""Tests for the outcome-driven submission dispatch redesign.

Covers: broadened attached-mail detection (rfc822 not named .eml), the outcome
model on SuspiciousMailResponse, the valid/invalid partition + de-dup, and the
slimmed bad-mail ack.
"""
import logging
import pathlib
import tempfile
import unittest
from email.message import EmailMessage
from unittest import mock

import main
import classes.models.mail as mail_models
from classes.models.mail_tags import SubmissionOutcome
from classes.services.mailbox_service import Mailbox


def _mailbox_for_extract() -> Mailbox:
    """A Mailbox usable for extract_attachments without an IMAP client."""
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _build_message_with_attachments() -> EmailMessage:
    outer = EmailMessage()
    outer["Subject"] = "wrapper"
    outer["From"] = "user@corp.com"
    outer.set_content("please analyse")

    # 1) An embedded mail named NOT .eml -> must still be detected (rfc822).
    inner = EmailMessage()
    inner["Subject"] = "phish"
    inner["From"] = "attacker@evil.test"
    inner.set_content("click here")
    outer.add_attachment(inner, filename="forwarded.txt")

    # 2) A .eml-named binary attachment -> detected by extension.
    outer.add_attachment(
        b"From: a@b\r\nSubject: x\r\n\r\nbody",
        maintype="application", subtype="octet-stream", filename="evidence.eml",
    )

    # 3) A plain document -> NOT a mail.
    outer.add_attachment(
        b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="doc.pdf",
    )
    return outer


class DetectionTests(unittest.TestCase):
    def test_is_email_flags(self):
        msg = _build_message_with_attachments()
        with tempfile.TemporaryDirectory() as d:
            mb = _mailbox_for_extract()
            atts = mb.extract_attachments(msg, pathlib.Path(d), "ref-1")
        by_kind = {}
        for a in atts:
            if a.filename.endswith(".pdf"):
                by_kind["pdf"] = a
            elif "forwarded" in a.filename:
                by_kind["rfc822"] = a
            elif a.filename.endswith(".eml"):
                by_kind["eml"] = a
        # rfc822 part not named .eml is still recognised as a mail.
        self.assertTrue(by_kind["rfc822"].is_email)
        self.assertTrue(by_kind["eml"].is_email)
        self.assertFalse(by_kind["pdf"].is_email)


def _response(outcome: SubmissionOutcome, submission_dir: str, rid: str = "r"):
    req = mail_models.SuspiciousMailRequest(
        id=b"1", to=[], cc=[], bcc=[], date=None, subject=None,
        from_address="user@corp.com", from_header_raw=None,
        body_text="", body_html="", headers_parsed={}, raw_eml_bytes=b"",
        attachments=[],
    )
    return mail_models.SuspiciousMailResponse(
        original_mail=req, id=rid, case_path=submission_dir + "/analysis",
        outcome=outcome, submission_dir=submission_dir,
    )


class PartitionTests(unittest.TestCase):
    def test_valid_and_invalid_split_with_dedup(self):
        mails = [
            _response(SubmissionOutcome.VALID, "/w/sub-a", "a1"),
            _response(SubmissionOutcome.VALID, "/w/sub-a", "a2"),   # same dir
            _response(SubmissionOutcome.VALID, "/w/sub-b", "b1"),
            _response(SubmissionOutcome.NO_ATTACHED_MAIL, "/w/sub-c", "c1"),
        ]
        valid_dirs, invalid = main.partition_submissions(mails)
        self.assertEqual(valid_dirs, ["/w/sub-a", "/w/sub-b"])  # deduped, ordered
        self.assertEqual([m.id for m in invalid], ["c1"])

    def test_response_requires_outcome_and_dir(self):
        with self.assertRaises(Exception):
            mail_models.SuspiciousMailResponse(
                original_mail=_response(SubmissionOutcome.VALID, "/x").original_mail,
                id="r", case_path="/x/a",
            )


class AckTests(unittest.TestCase):
    def test_send_bad_mail_ack_targets_sender(self):
        from classes.services.acknowledge_bad_mail_service import (
            AcknowledgeBadMailService,
        )
        svc = AcknowledgeBadMailService.__new__(AcknowledgeBadMailService)
        svc._AcknowledgeBadMailService__logger = logging.getLogger("test")
        mail = _response(SubmissionOutcome.NO_ATTACHED_MAIL, "/w/sub")
        with mock.patch.object(
            AcknowledgeBadMailService, "send_user_acknowledgement_email"
        ) as send:
            svc.send_bad_mail_ack(mail)
        send.assert_called_once_with("user@corp.com")


if __name__ == "__main__":
    unittest.main()
