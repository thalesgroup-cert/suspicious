import json
import os
import tempfile
import unittest

from common.storage import FakeObjectStore
from tasp.cron.prefix_source import PrefixSource
from mail_feeder import submission_contract as sc

BUCKET = "feeder-bucket"


def _status(state, sid, **extra):
    return sc.build_status(
        state, submission_id=sid, reported_by="u@x",
        emails_to_analyze=extra.pop("emails", []), attachments=[])


def _put(store, key, body: bytes):
    import io
    store.put(BUCKET, key, io.BytesIO(body), length=len(body))


def _put_status(store, sid, manifest):
    _put(store, f"{sid}/_status.json", json.dumps(manifest).encode())


def _read_status(store, sid):
    with store.open(BUCKET, f"{sid}/_status.json") as s:
        return json.loads(s.read())


class PrefixSourceTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeObjectStore()
        self.store.ensure_bucket(BUCKET)
        self.src = PrefixSource(self.store, BUCKET)

    def test_iter_pending_yields_todo_and_processing_not_done(self):
        for sid, state in (("260326141159-aaa", sc.STATUS_TODO),
                           ("260326141200-bbb", sc.STATUS_DONE),
                           ("260326141201-ccc", sc.STATUS_PROCESSING)):
            _put_status(self.store, sid, _status(state, sid))
        _put(self.store, "260326141202-ddd/no-status.txt", b"x")

        self.assertEqual(
            list(self.src.iter_pending()),
            ["260326141159-aaa", "260326141201-ccc"],
        )

    def test_mark_email_done_appends_and_persists(self):
        sid = "260326141159-aaa"
        _put_status(self.store, sid, _status(sc.STATUS_PROCESSING, sid, emails=["a", "b"]))

        self.src.mark_email_done(sid, "260326141159-bbb")

        written = _read_status(self.store, sid)
        self.assertEqual(written["processed_emails"], ["260326141159-bbb"])
        self.assertEqual(written["status"], "processing")

    def test_mark_email_done_is_idempotent(self):
        sid = "260326141159-aaa"
        original = _status(sc.STATUS_PROCESSING, sid)
        original["processed_emails"] = ["260326141159-bbb"]
        _put_status(self.store, sid, original)
        before = self.store.stat(BUCKET, f"{sid}/_status.json")

        self.src.mark_email_done(sid, "260326141159-bbb")

        self.assertEqual(self.store.stat(BUCKET, f"{sid}/_status.json"), before)
        self.assertEqual(_read_status(self.store, sid)["processed_emails"], ["260326141159-bbb"])

    def test_set_status_overwrites_preserving_fields(self):
        sid = "260326141159-aaa"
        _put_status(self.store, sid, _status(sc.STATUS_TODO, sid, emails=["a"]))

        self.src.set_status(sid, sc.STATUS_PROCESSING)

        written = _read_status(self.store, sid)
        self.assertEqual(written["status"], "processing")
        self.assertEqual(written["reported_by"], "u@x")
        self.assertEqual(written["emails_to_analyze"], ["a"])


class PrefixDownloadTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeObjectStore()
        self.store.ensure_bucket(BUCKET)
        self.src = PrefixSource(self.store, BUCKET)

    def test_download_returns_wrapper_path_and_writes_files(self):
        for key in ("user-submission.eml", "260326141159-bbb/ref.eml", "_status.json"):
            _put(self.store, f"260326141159-aaa/{key}", b"x")

        with tempfile.TemporaryDirectory() as d:
            wrapper = self.src.download_submission("260326141159-aaa", d)
            self.assertTrue(wrapper.endswith("user-submission.eml"))
            self.assertTrue(os.path.exists(
                os.path.join(d, "260326141159-aaa", "260326141159-bbb", "ref.eml")))
            self.assertFalse(os.path.exists(
                os.path.join(d, "260326141159-aaa", "_status.json")))

    def test_download_no_wrapper_returns_none(self):
        _put(self.store, "260326141159-aaa/_status.json", b"{}")
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(self.src.download_submission("260326141159-aaa", d))
