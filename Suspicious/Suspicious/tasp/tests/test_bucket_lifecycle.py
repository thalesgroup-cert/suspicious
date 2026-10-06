import os
import tempfile
import unittest
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase

from tasp.cron import fetch_emails as fe

BUCKET = "jordan.kim-submission-261006145515"
LOCK = f"lock:minio_bucket:{BUCKET}"


def _fake_client(status):
    client = mock.MagicMock()
    bucket = mock.Mock()
    bucket.name = BUCKET
    client.list_buckets.return_value = [bucket]
    client.get_bucket_tags.return_value = {"Status": status}
    objs = []
    for name in ("u-submission.eml", "261006145515-abc/261006145515-abc.eml"):
        obj = mock.Mock()
        obj.object_name = name
        objs.append(obj)
    client.list_objects.return_value = objs

    def fget(_bucket, _name, dst):
        with open(dst, "wb") as f:
            f.write(b"From: u@x\r\n\r\nbody")

    client.fget_object.side_effect = fget
    return client


def _tags_set(client):
    return [c.args[1]["Status"] for c in client.set_bucket_tags.call_args_list]


class HandoffFailureTests(unittest.TestCase):
    def test_handoff_reports_emails_the_processor_failed_on(self):
        with tempfile.TemporaryDirectory() as d:
            wrapper = os.path.join(d, "u-submission.eml")
            open(wrapper, "wb").write(b"From: u@x\r\n\r\nbody")
            ok_dir, bad_dir = "260326141159-abc", "260326141200-def"
            for name in (ok_dir, bad_dir):
                os.makedirs(os.path.join(d, name))
            processor = mock.Mock()
            processor.process_emails_from_minio_workdir.side_effect = (
                lambda workdir, *a, **k: os.path.basename(workdir) != bad_dir
            )
            failed = fe._handoff_submission(d, wrapper, "b", "u@x", processor)
            self.assertEqual(failed, [bad_dir])


class BucketTagTests(SimpleTestCase):
    def setUp(self):
        cache.delete(LOCK)
        self.base = tempfile.mkdtemp()

    def tearDown(self):
        cache.delete(LOCK)

    def _run(self, status, failed, ingested=frozenset()):
        client = _fake_client(status)
        with mock.patch.object(fe, "_init_minio_client", return_value=client), \
                mock.patch.object(fe, "MinioEmailService"), \
                mock.patch.object(fe, "_already_ingested", return_value=set(ingested)), \
                mock.patch.object(fe, "_handoff_submission", return_value=failed) as handoff:
            fe._process_minio_buckets(self.base)
        self.handoff = handoff
        return client

    def test_clean_bucket_is_tagged_done(self):
        self.assertEqual(_tags_set(self._run("To Do", [])), ["Processing", "Done"])

    def test_bucket_with_failed_emails_is_tagged_error_not_done(self):
        self.assertEqual(_tags_set(self._run("To Do", ["260326141200-def"])), ["Processing", "Error"])

    def test_error_bucket_is_not_retried(self):
        self.assertEqual(_tags_set(self._run("Error", [])), [])

    def test_stale_processing_bucket_is_reclaimed(self):
        # tagged Processing but no live run holds its lock: the worker was killed
        self.assertEqual(_tags_set(self._run("Processing", [])), ["Processing", "Done"])

    def test_processing_bucket_with_live_lock_is_left_alone(self):
        cache.add(LOCK, "1", timeout=900)
        self.assertEqual(_tags_set(self._run("Processing", [])), [])

    def test_reclaimed_bucket_skips_emails_that_already_have_a_case(self):
        # the killed run had already ingested this email; redoing it would duplicate the case
        self._run("Processing", [], ingested={"261006145515-abc"})
        self.assertEqual(self.handoff.call_args.kwargs["done_emails"], {"261006145515-abc"})

    def test_normal_bucket_does_not_consult_the_database(self):
        self._run("To Do", [], ingested={"261006145515-abc"})
        self.assertEqual(self.handoff.call_args.kwargs.get("done_emails", frozenset()), frozenset())
