import email
import email.policy
import hashlib

from mail_feeder import email_contract as ec


def _msg():
    import email.message
    m = email.message.EmailMessage()
    m["From"] = "Alice <ALICE@Example.TEST>"
    m["To"] = "bob@example.test"
    m["Subject"] = "Hello"
    m.set_content("plain body")
    m.add_attachment(b"PDFDATA", maintype="application", subtype="pdf",
                     filename="report.pdf")
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)


def test_build_metadata_matches_feeder_semantics():
    meta = ec.build_email_metadata(_msg(), "260625140959-aa")
    assert meta.from_ == "alice@example.test"
    assert meta.attachments[0].sha256 == hashlib.sha256(b"PDFDATA").hexdigest()
    assert ec.EmailMetadata.model_validate(meta.model_dump(by_alias=True))
