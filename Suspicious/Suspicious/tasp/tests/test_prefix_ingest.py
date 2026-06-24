import os
import sys
import tempfile
import unittest
from unittest import mock

# Stub out the dependency chain that requires native libs not available in test env.
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

        # iter_pending sees one todo prefix.
        from tasp.cron.prefix_source import PrefixSource
        with mock.patch.object(PrefixSource, "iter_pending",
                               return_value=iter(["260326141159-aaa"])), \
             mock.patch.object(PrefixSource, "download_submission") as dl, \
             mock.patch.object(PrefixSource, "set_status") as setst, \
             mock.patch.object(fe, "_handoff_submission") as handoff, \
             tempfile.TemporaryDirectory() as d:

            wrapper = os.path.join(d, "260326141159-aaa", "u-submission.eml")
            os.makedirs(os.path.dirname(wrapper), exist_ok=True)
            open(wrapper, "wb").close()
            dl.return_value = wrapper

            fe._process_prefix_submissions(d, "feeder-bucket")

            # processing then done
            self.assertEqual(
                [c.args[1] for c in setst.call_args_list],
                [sc.STATUS_PROCESSING, sc.STATUS_DONE],
            )
            handoff.assert_called_once()
