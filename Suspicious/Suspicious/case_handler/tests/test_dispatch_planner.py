from unittest import mock
from django.test import TestCase

from case_handler.case_utils.case_handler import CaseHandler
from url_process.models import URL


class DispatchPlannerTest(TestCase):
    def _handler_with_url_intents(self, urls):
        h = CaseHandler.__new__(CaseHandler)
        h.pending_dispatch_intents = [(u, "url") for u in urls]
        return h

    def _fake_mail_case(self):
        case = mock.Mock()
        case.id = 1
        case.fileOrMail = mock.Mock(mail_id=99)
        return case

    @mock.patch("url_process.url_utils.url_planner.get_config")
    @mock.patch("case_handler.case_utils.case_handler.CortexJob")
    def test_enabled_dispatches_only_survivors(self, CortexJob, get_config):
        get_config.side_effect = lambda k, d=None: {"url_analysis.enabled": True,
                                                     "url_analysis.max_per_domain": 1}.get(k, d)
        urls = [URL.objects.create(address=f"https://x.com/p?id={i}") for i in range(4)]
        h = self._handler_with_url_intents(urls)
        h.dispatch_pending(self._fake_mail_case())
        self.assertEqual(CortexJob.return_value.launch_cortex_jobs.call_count, 1)

    @mock.patch("url_process.url_utils.url_planner.get_config")
    @mock.patch("case_handler.case_utils.case_handler.CortexJob")
    def test_disabled_dispatches_all(self, CortexJob, get_config):
        get_config.side_effect = lambda k, d=None: {"url_analysis.enabled": False}.get(k, d)
        urls = [URL.objects.create(address=f"https://x.com/a{i}") for i in range(4)]
        h = self._handler_with_url_intents(urls)
        h.dispatch_pending(self._fake_mail_case())
        self.assertEqual(CortexJob.return_value.launch_cortex_jobs.call_count, 4)
