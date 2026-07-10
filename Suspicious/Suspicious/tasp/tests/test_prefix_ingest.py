import os
import sys
import tempfile
import unittest
from unittest import mock

for _mod in [
    "cortex4py",
    "cortex4py.api",
    "cortex4py.controllers",
    "cortex4py.controllers.organizations",
    "cortex4py.controllers.analyzers",
    "magic",
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = mock.MagicMock()

from tasp.cron import fetch_emails as fe
from mail_feeder import submission_contract as sc


class PrefixIngestTests(unittest.TestCase):
    @mock.patch.object(fe, "MinioEmailService")
    @mock.patch.object(fe, "_init_minio_client")
    def test_pending_prefix_is_processed_and_marked_done(self, mock_init, mock_proc_cls):
        client = mock.Mock()
        mock_init.return_value = client

        from tasp.cron.prefix_source import PrefixSource
        with mock.patch.object(PrefixSource, "iter_pending",
                               return_value=iter(["260326141159-aaa"])), \
             mock.patch.object(PrefixSource, "download_submission") as dl, \
             mock.patch.object(PrefixSource, "set_status") as setst, \
             mock.patch.object(PrefixSource, "read_status",
                               return_value={"reported_by": "reporter@example.com"}), \
             mock.patch.object(fe, "_handoff_submission") as handoff, \
             tempfile.TemporaryDirectory() as d:

            wrapper = os.path.join(d, "260326141159-aaa", "u-submission.eml")
            os.makedirs(os.path.dirname(wrapper), exist_ok=True)
            open(wrapper, "wb").close()
            dl.return_value = wrapper

            fe._process_prefix_submissions(d, "feeder-bucket")

            self.assertEqual(
                [c.args[1] for c in setst.call_args_list],
                [sc.STATUS_PROCESSING, sc.STATUS_DONE],
            )
            handoff.assert_called_once()
            self.assertEqual(handoff.call_args.args[3], "reporter@example.com")
            self.assertEqual(handoff.call_args.kwargs["done_emails"], set())
            self.assertTrue(callable(handoff.call_args.kwargs["on_email_done"]))

    @mock.patch.object(fe, "MinioEmailService")
    @mock.patch.object(fe, "_init_minio_client")
    def test_reclaimed_submission_skips_already_processed_emails(self, mock_init, mock_proc_cls):
        client = mock.Mock()
        mock_init.return_value = client

        from tasp.cron.prefix_source import PrefixSource
        with mock.patch.object(PrefixSource, "iter_pending",
                               return_value=iter(["260326141159-aaa"])), \
             mock.patch.object(PrefixSource, "download_submission") as dl, \
             mock.patch.object(PrefixSource, "set_status"), \
             mock.patch.object(PrefixSource, "read_status",
                               return_value={"reported_by": "reporter@example.com",
                                             "processed_emails": ["260326141159-bbb"]}), \
             mock.patch.object(fe, "_handoff_submission") as handoff, \
             tempfile.TemporaryDirectory() as d:

            wrapper = os.path.join(d, "260326141159-aaa", "u-submission.eml")
            os.makedirs(os.path.dirname(wrapper), exist_ok=True)
            open(wrapper, "wb").close()
            dl.return_value = wrapper

            fe._process_prefix_submissions(d, "feeder-bucket")

            self.assertEqual(
                handoff.call_args.kwargs["done_emails"], {"260326141159-bbb"})
