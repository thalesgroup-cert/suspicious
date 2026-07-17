from unittest import mock
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from tasp.tasks import dispatch_case_analysis
from url_process.models import URL


class DispatchPlannerTest(TestCase):
    """URL-planner filtering now runs inside dispatch_case_analysis (the
    async task CaseHandler.dispatch_pending enqueues), not inline in the
    request. Drive it the same way the task itself is invoked: serialized
    (app_label.model, pk, data_type) intents."""

    def setUp(self):
        user = get_user_model().objects.create_user(username="planner_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    def _intents_for(self, urls):
        return [(f"{u._meta.app_label}.{u._meta.model_name}", u.pk, "url") for u in urls]

    @mock.patch("tasp.tasks.reconcile_case.delay")
    @mock.patch("url_process.url_utils.url_planner.get_config")
    @mock.patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_enabled_dispatches_only_survivors(self, CortexJob, get_config, mock_reconcile):
        get_config.side_effect = lambda k, d=None: {
            "url_analysis.enabled": True,
            "url_analysis.max_per_domain": 1,
        }.get(k, d)
        urls = [URL.objects.create(address=f"https://x.com/p?id={i}") for i in range(4)]

        dispatch_case_analysis.run(self.case.id, self._intents_for(urls))

        self.assertEqual(CortexJob.return_value.launch_cortex_jobs.call_count, 1)

    @mock.patch("tasp.tasks.reconcile_case.delay")
    @mock.patch("url_process.url_utils.url_planner.get_config")
    @mock.patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob")
    def test_disabled_dispatches_all(self, CortexJob, get_config, mock_reconcile):
        get_config.side_effect = lambda k, d=None: {"url_analysis.enabled": False}.get(k, d)
        urls = [URL.objects.create(address=f"https://x.com/a{i}") for i in range(4)]

        dispatch_case_analysis.run(self.case.id, self._intents_for(urls))

        self.assertEqual(CortexJob.return_value.launch_cortex_jobs.call_count, 4)
