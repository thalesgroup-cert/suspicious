import json
import pathlib
import tempfile
from unittest import mock

from classes.services.submission_sink import PrefixSink
import classes.models.submission_contract as sc


def _make_submission(root: pathlib.Path):
    sid = "260326141159-aaa"
    base = root / sid
    base.mkdir(parents=True)
    (base / "jane-submission.eml").write_bytes(b"From: jane@x\r\n\r\nwrap")
    inner = base / "260326141159-bbb"
    inner.mkdir()
    (inner / "ref.eml").write_bytes(b"inner eml")
    (inner / "attachments").mkdir()
    (inner / "attachments" / "x.pdf").write_bytes(b"%PDF")
    return sid, base


def test_store_uploads_prefix_and_status_last():
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        sid, base = _make_submission(root)

        svc = mock.Mock()
        order = []
        svc.upload_file.side_effect = lambda **kw: order.append(kw["object_name"])
        svc.upload_bytes.side_effect = lambda **kw: order.append(kw["object_name"])

        sink = PrefixSink(svc, "feeder")
        sink.store(base, sid, "jane@x")

        svc.ensure_bucket.assert_called_once_with("feeder")
        assert order[-1] == f"{sid}/{sc.STATUS_OBJECT_NAME}"
        assert all(name.startswith(sid + "/") for name in order)

        _, kw = svc.upload_bytes.call_args
        manifest = json.loads(kw["data"])
        assert any(k.endswith("/ref.eml") for k in manifest["emails_to_analyze"])
        assert all("submission.eml" not in k for k in manifest["emails_to_analyze"])
        assert any(k.endswith("x.pdf") for k in manifest["attachments"])
        assert manifest["reported_by"] == "jane@x"
        assert manifest["submission_id"] == sid


def test_email_json_not_listed_as_email_or_attachment(tmp_path):
    # build a submission dir with an analyzed email dir containing email.json
    sub = tmp_path / "260625140959-aa"
    edir = sub / "260625140959-bb"
    edir.mkdir(parents=True)
    (edir / "260625140959-bb.eml").write_bytes(b"From: a@b\n\nx")
    (edir / "email.json").write_text("{}")
    captured = {}
    class FakeSvc:
        def ensure_bucket(self, b): pass
        def upload_file(self, **k): pass
        def upload_bytes(self, bucket_name, object_name, data, content_type):
            captured["status"] = data
    import classes.services.submission_sink as ss
    ss.PrefixSink(FakeSvc(), "bucket").store(sub, "260625140959-aa", "u@x")
    import json
    manifest = json.loads(captured["status"])
    joined = manifest["emails_to_analyze"] + manifest["attachments"]
    assert not any(o.endswith("email.json") for o in joined)
    assert any(o.endswith(".eml") for o in manifest["emails_to_analyze"])


def test_store_writes_reporter_note(tmp_path):
    sub = tmp_path / "260625140959-aa"
    edir = sub / "260625140959-bb"; edir.mkdir(parents=True)
    (edir / "260625140959-bb.eml").write_bytes(b"From: a@b\n\nx")
    captured = {}
    class FakeSvc:
        def ensure_bucket(self, b): pass
        def upload_file(self, **k): pass
        def upload_bytes(self, bucket_name, object_name, data, content_type):
            captured["status"] = data
    import classes.services.submission_sink as ss, json
    ss.PrefixSink(FakeSvc(), "bucket").store(
        sub, "260625140959-aa", "u@x", reporter_note="check this please")
    assert json.loads(captured["status"])["reporter_note"] == "check this please"
