import email.message
import email.policy

import classes.models.email_contract as ec


def _msg():
    m = email.message.EmailMessage()
    m["From"] = "Alice <ALICE@Example.TEST>"
    m["To"] = "bob@example.test"
    m["Subject"] = "Hello"
    m.set_content("plain body")
    m.add_attachment(b"PDFDATA", maintype="application", subtype="pdf",
                     filename="report.pdf")
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)


def test_extract_address_lowercases_first():
    assert ec.extract_address("Alice <ALICE@Example.TEST>") == "alice@example.test"
    assert ec.extract_address("") is None
    assert ec.extract_address(None) is None


def test_build_email_metadata_full():
    meta = ec.build_email_metadata(_msg(), "260625140959-aa")
    assert meta.id == "260625140959-aa"
    assert meta.from_ == "alice@example.test"
    assert meta.to == "bob@example.test"
    assert meta.reportedSubject == "Hello"
    assert any("plain body" in t for t in meta.reportedText)
    assert meta.headers.get("Subject") == "Hello"
    assert len(meta.attachments) == 1
    att = meta.attachments[0]
    assert att.filename == "report.pdf"
    import hashlib
    assert att.sha256 == hashlib.sha256(b"PDFDATA").hexdigest()


def test_metadata_is_validatable_wire_dict():
    meta = ec.build_email_metadata(_msg(), "260625140959-aa")
    dumped = meta.model_dump(by_alias=True)
    # round-trips through validation (proves writer output is contract-valid)
    assert ec.EmailMetadata.model_validate(dumped).from_ == "alice@example.test"


def test_resolve_reporter_and_to():
    # empty/undisclosed to -> default; reporter falls back to to
    assert ec.resolve_reporter_and_to(None, "") == (
        "no.recipient@noemail.com", "no.recipient@noemail.com")
    assert ec.resolve_reporter_and_to("Undisclosed recipients:;", "") == (
        "no.recipient@noemail.com", "no.recipient@noemail.com")
    # explicit reporter wins, to preserved
    assert ec.resolve_reporter_and_to("victim@corp.test", "rep@corp.test") == (
        "victim@corp.test", "rep@corp.test")
    # no reporter -> reporter is the (possibly defaulted) to
    assert ec.resolve_reporter_and_to("victim@corp.test", "") == (
        "victim@corp.test", "victim@corp.test")
