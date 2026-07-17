import pydantic
import pytest

import classes.models.submission_contract as sc


def test_constants_and_regex():
    assert sc.STATUS_OBJECT_NAME == "_status.json"
    assert sc.SUBMISSION_EML_SUFFIX == "submission.eml"
    assert sc.STATUS_TODO == "todo"
    assert sc.CONTRACT_SCHEMA == 1
    assert sc.EMAIL_DIR_PATTERN.match("260326141159-abc123")
    assert not sc.EMAIL_DIR_PATTERN.match("analysis_0")


def test_build_status_shape():
    s = sc.build_status(
        submission_id="260326141159-aa",
        reported_by="u@x",
        emails_to_analyze=["260326141159-bb/ref.eml"],
        attachments=["260326141159-bb/attachments/x.pdf"],
    )
    assert s["schema"] == 1
    assert s["status"] == "todo"
    assert s["submission_id"] == "260326141159-aa"
    assert s["reported_by"] == "u@x"
    assert s["emails_to_analyze"] == ["260326141159-bb/ref.eml"]
    assert "submitted_at" in s and s["submitted_at"]


# --- Data validation (fail fast at write time, not on the backend reader) ---

def _valid_kwargs(**over):
    base = dict(
        submission_id="260326141159-aa",
        reported_by="u@x",
        emails_to_analyze=["260326141159-aa/ref.eml"],
        attachments=[],
    )
    base.update(over)
    return base


def test_build_status_output_validates_against_model():
    s = sc.build_status(**_valid_kwargs())
    model = sc.SubmissionStatus.model_validate(s)
    assert model.status == sc.STATUS_TODO
    assert model.submission_id == "260326141159-aa"
    # Round-trips back to the exact wire dict (schema key, not python attr name).
    assert model.model_dump(by_alias=True) == s


def test_build_status_rejects_empty_submission_id():
    with pytest.raises(pydantic.ValidationError):
        sc.build_status(**_valid_kwargs(submission_id=""))


def test_build_status_rejects_unknown_status():
    with pytest.raises(pydantic.ValidationError):
        sc.build_status(**_valid_kwargs(status="bogus"))


def test_build_status_rejects_non_string_email_entries():
    with pytest.raises(pydantic.ValidationError):
        sc.build_status(**_valid_kwargs(emails_to_analyze=[123]))


def test_build_status_rejects_bad_submitted_at():
    with pytest.raises(pydantic.ValidationError):
        sc.build_status(**_valid_kwargs(submitted_at="not-a-timestamp"))


def test_model_forbids_unknown_fields():
    s = sc.build_status(**_valid_kwargs())
    s["surprise"] = "drift"
    with pytest.raises(pydantic.ValidationError):
        sc.SubmissionStatus.model_validate(s)


def test_model_rejects_wrong_schema_version():
    s = sc.build_status(**_valid_kwargs())
    s["schema"] = 2
    with pytest.raises(pydantic.ValidationError):
        sc.SubmissionStatus.model_validate(s)


def test_build_status_carries_reporter_note():
    s = sc.build_status(
        submission_id="260625140959-aa", reported_by="u@x",
        emails_to_analyze=[], attachments=[], reporter_note="please check this",
    )
    assert s["reporter_note"] == "please check this"
    assert sc.SubmissionStatus.model_validate(s).reporter_note == "please check this"


def test_build_status_default_reporter_note_empty():
    s = sc.build_status(submission_id="260625140959-aa", reported_by="u@x",
                        emails_to_analyze=[], attachments=[])
    assert s["reporter_note"] == ""
