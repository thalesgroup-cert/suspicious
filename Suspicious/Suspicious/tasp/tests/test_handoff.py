import os
import sys
import tempfile
import unittest
from unittest import mock

# Mock out the problematic dependency chain before importing fetch_emails
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
            # A non-matching dir must be ignored.
            os.makedirs(os.path.join(d, "analysis_0"))

            processor = mock.Mock()
            _handoff_submission(d, wrapper, "bucket-id", "u@x", processor)

            self.assertTrue(os.path.exists(
                os.path.join(email_dir, "user_submission.eml")))
            processor.process_emails_from_minio_workdir.assert_called_once_with(
                email_dir, "bucket-id", reported_by="u@x")
