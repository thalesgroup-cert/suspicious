import email.message
import email.policy
import json
import logging
import pathlib
import tempfile
import classes.models.email_contract as ec
from classes.services.mailbox_service import Mailbox


def _mb():
    mb = Mailbox.__new__(Mailbox)
    mb._Mailbox__logger = logging.getLogger("test")
    return mb


def _inner():
    m = email.message.EmailMessage()
    m["From"] = "att@evil.test"
    m["Subject"] = "phish"
    m.set_content("click")
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)


def test_email_json_written_next_to_eml():
    mb = _mb()
    with tempfile.TemporaryDirectory() as d:
        resp = mb.process_attachment_email(
            email_id=b"1", msg=_inner(),
            parent_dir_for_analysis=pathlib.Path(d),
            source_ref="260625140959-dddddddddddd",
        )
        meta_path = pathlib.Path(resp.case_path) / ec.EMAIL_METADATA_OBJECT_NAME
        assert meta_path.is_file()
        data = json.loads(meta_path.read_text())
        assert ec.EmailMetadata.model_validate(data).reportedSubject == "phish"
