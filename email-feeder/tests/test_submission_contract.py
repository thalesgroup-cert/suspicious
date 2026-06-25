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
