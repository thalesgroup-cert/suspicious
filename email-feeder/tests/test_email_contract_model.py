import pydantic
import pytest

import classes.models.email_contract as ec


def _valid():
    return {
        "schema": 1, "id": "260625140959-aa", "from": "a@x.test",
        "to": "b@y.test", "cc": None, "bcc": None,
        "reportedSubject": "hi", "reportedText": ["body"],
        "date": "Mon, 1 Jan 2026 00:00:00 +0000", "headers": {"From": "a@x.test"},
        "attachments": [{"filename": "x.pdf", "sha256": "0" * 64, "headers": {}}],
    }


def test_validates_and_roundtrips_by_alias():
    m = ec.EmailMetadata.model_validate(_valid())
    assert m.from_ == "a@x.test"
    assert m.schema_version == 1
    assert m.model_dump(by_alias=True) == _valid()


def test_forbids_unknown_keys():
    bad = _valid() | {"surprise": 1}
    with pytest.raises(pydantic.ValidationError):
        ec.EmailMetadata.model_validate(bad)


def test_rejects_wrong_schema():
    bad = _valid() | {"schema": 2}
    with pytest.raises(pydantic.ValidationError):
        ec.EmailMetadata.model_validate(bad)


def test_attachment_sha256_must_be_64_hex():
    bad = _valid()
    bad["attachments"][0]["sha256"] = "nothex"
    with pytest.raises(pydantic.ValidationError):
        ec.EmailMetadata.model_validate(bad)


def test_object_name_constant():
    assert ec.EMAIL_METADATA_OBJECT_NAME == "email.json"
