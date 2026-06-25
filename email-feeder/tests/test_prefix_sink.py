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
