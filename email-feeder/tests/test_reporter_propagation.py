"""The reporter (the person who forwarded a suspicious mail) must be carried
onto the submission response so the prefix-contract `reported_by` names them,
not the inner attacker address. Regression guard for the bug surfaced by the
greenmail e2e: forwarded submissions wrote `reported_by: ""`.
"""
import email.message
import email.policy
import logging
import pathlib
import tempfile

import classes.models.mail_tags as mail_tags
from classes.services.mailbox_service import Mailbox


def _mb():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _inner_attacker_mail() -> email.message.EmailMessage:
    m = email.message.EmailMessage()
    m["From"] = "attacker@evil.test"
    m["To"] = "victim@corp.com"
    m["Subject"] = "click here"
    m.set_content("http://phish.evil.test/login")
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)


def test_attachment_email_carries_reporter_not_inner_from():
    inner = _inner_attacker_mail()
    mb = _mb()
    with tempfile.TemporaryDirectory() as d:
        resp = mb.process_attachment_email(
            email_id=b"1",
            msg=inner,
            parent_dir_for_analysis=pathlib.Path(d),
            source_ref="260625140959-aaaaaaaaaaaa",
            reported_by="reporter@corp.com",
        )
    assert resp is not None
    assert resp.outcome == mail_tags.SubmissionOutcome.VALID
    # reported_by names the forwarding employee, never the inner attacker.
    assert resp.reported_by == "reporter@corp.com"
    assert resp.original_mail.from_address == "attacker@evil.test"


def test_response_reported_by_defaults_empty():
    # Field exists with a safe default so non-forwarded paths stay valid.
    inner = _inner_attacker_mail()
    mb = _mb()
    with tempfile.TemporaryDirectory() as d:
        resp = mb.process_attachment_email(
            email_id=b"1", msg=inner,
            parent_dir_for_analysis=pathlib.Path(d),
            source_ref="260625140959-bbbbbbbbbbbb",
        )
    assert resp.reported_by == ""


def test_attachment_email_carries_reporter_note():
    inner = _inner_attacker_mail()
    mb = _mb()
    import pathlib
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        resp = mb.process_attachment_email(
            email_id=b"1", msg=inner,
            parent_dir_for_analysis=pathlib.Path(d),
            source_ref="260625140959-cccccccccccc",
            reported_by="reporter@corp.com", reporter_note="please analyse",
        )
    assert resp.reporter_note == "please analyse"
