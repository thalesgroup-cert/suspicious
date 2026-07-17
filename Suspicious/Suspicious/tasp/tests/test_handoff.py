import os
import sys
import tempfile
import unittest
from unittest import mock

sys.modules["cortex4py"] = mock.MagicMock()
sys.modules["cortex4py.api"] = mock.MagicMock()
sys.modules["cortex4py.controllers"] = mock.MagicMock()
sys.modules["cortex4py.controllers.organizations"] = mock.MagicMock()
sys.modules["cortex4py.controllers.analyzers"] = mock.MagicMock()
sys.modules["magic"] = mock.MagicMock()

from tasp.cron.fetch_emails import _handoff_submission


class HandoffTests(unittest.TestCase):
    def test_copies_wrapper_and_invokes_processor_per_email_dir(self):
        with tempfile.TemporaryDirectory() as d:
            wrapper = os.path.join(d, "u-submission.eml")
            with open(wrapper, "wb") as f:
                f.write(b"From: u@x\r\n\r\nbody")
            email_dir = os.path.join(d, "260326141159-abc")
            os.makedirs(email_dir)
            with open(os.path.join(email_dir, "ref.eml"), "wb") as f:
                f.write(b"inner")
            os.makedirs(os.path.join(d, "analysis_0"))

            processor = mock.Mock()
            _handoff_submission(d, wrapper, "bucket-id", "u@x", processor)

            self.assertTrue(os.path.exists(
                os.path.join(email_dir, "user_submission.eml")))
            processor.process_emails_from_minio_workdir.assert_called_once_with(
                email_dir, "bucket-id", reported_by="u@x", reporter_note="")

    def test_skips_done_emails_and_marks_each_processed(self):
        with tempfile.TemporaryDirectory() as d:
            wrapper = os.path.join(d, "u-submission.eml")
            with open(wrapper, "wb") as f:
                f.write(b"From: u@x\r\n\r\nbody")
            done_dir = os.path.join(d, "260326141159-abc")
            todo_dir = os.path.join(d, "260326141200-def")
            for p in (done_dir, todo_dir):
                os.makedirs(p)
                with open(os.path.join(p, "ref.eml"), "wb") as f:
                    f.write(b"inner")

            processor = mock.Mock()
            marked = []
            _handoff_submission(
                d, wrapper, "bucket-id", "u@x", processor,
                done_emails={"260326141159-abc"},
                on_email_done=marked.append,
            )

            processor.process_emails_from_minio_workdir.assert_called_once_with(
                todo_dir, "bucket-id", reported_by="u@x", reporter_note="")
            self.assertFalse(os.path.exists(
                os.path.join(done_dir, "user_submission.eml")))
            self.assertEqual(marked, ["260326141200-def"])
