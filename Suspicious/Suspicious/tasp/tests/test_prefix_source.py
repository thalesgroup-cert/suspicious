import io
import json
import unittest
from unittest import mock

from tasp.cron.prefix_source import PrefixSource
from mail_feeder import submission_contract as sc


def _obj(name, is_dir=False):
    m = mock.Mock()
    m.object_name = name
    m.is_dir = is_dir
    return m


def _resp(body: bytes):
    r = mock.Mock()
    r.read.return_value = body
    return r


class PrefixSourceTests(unittest.TestCase):
    def setUp(self):
        self.client = mock.Mock()
        self.src = PrefixSource(self.client, "feeder-bucket")

    def test_iter_pending_yields_only_todo(self):
        # Two submission prefixes at the bucket root.
        self.client.list_objects.return_value = [
            _obj("260326141159-aaa/", is_dir=True),
            _obj("260326141200-bbb/", is_dir=True),
        ]
        statuses = {
            "260326141159-aaa/_status.json": sc.build_status(
                sc.STATUS_TODO, submission_id="260326141159-aaa",
                reported_by="u@x", emails_to_analyze=[], attachments=[]),
            "260326141200-bbb/_status.json": sc.build_status(
                sc.STATUS_DONE, submission_id="260326141200-bbb",
                reported_by="u@x", emails_to_analyze=[], attachments=[]),
        }

        def get_object(bucket, name):
            return _resp(json.dumps(statuses[name]).encode())

        self.client.get_object.side_effect = get_object

        self.assertEqual(list(self.src.iter_pending()), ["260326141159-aaa"])

    def test_set_status_overwrites_preserving_fields(self):
        original = sc.build_status(
            sc.STATUS_TODO, submission_id="260326141159-aaa",
            reported_by="u@x", emails_to_analyze=["a"], attachments=[])
        self.client.get_object.return_value = _resp(json.dumps(original).encode())

        self.src.set_status("260326141159-aaa", sc.STATUS_PROCESSING)

        args, kwargs = self.client.put_object.call_args
        written = json.loads(kwargs["data"].read())
        self.assertEqual(written["status"], "processing")
        self.assertEqual(written["reported_by"], "u@x")
        self.assertEqual(written["emails_to_analyze"], ["a"])
        self.assertEqual(kwargs["object_name"], "260326141159-aaa/_status.json")
