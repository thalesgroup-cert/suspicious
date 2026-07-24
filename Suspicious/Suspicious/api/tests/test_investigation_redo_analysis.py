from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL

User = get_user_model()


def _make_user(username, *, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class InvestigationRedoAnalysisTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("redo_reporter")
        self.analyst = _make_user("redo_analyst", groups=["CERT"])
        self.url = URL.objects.create(address="http://example.com")

    def _make_case(self, lifecycle_state):
        # ponytail: CaseHasNonFileIocs.case is a required FK (see
        # case_handler/migrations/0001_initial.py), so the case must exist
        # before the iocs row, then get linked back — matches the pattern
        # every other test in this repo uses (e.g. cortex_job/tests/
        # test_case_targets.py), not create(nonFileIocs=...) up front.
        case = Case.objects.create(
            reporter=self.reporter, description="", lifecycle_state=lifecycle_state,
        )
        iocs = CaseHasNonFileIocs.objects.create(case=case, url=self.url)
        case.nonFileIocs = iocs
        case.save()
        return case

    def _redo_url(self, case):
        return reverse("investigation-redo-analysis", kwargs={"case_id": case.id})

    def test_reporter_forbidden(self):
        case = self._make_case(LifecycleState.FINALIZED)
        self.client.force_authenticate(self.reporter)
        resp = self.client.post(self._redo_url(case))
        self.assertEqual(resp.status_code, 403)

    def test_non_terminal_case_returns_409(self):
        case = self._make_case(LifecycleState.ANALYZING)
        self.client.force_authenticate(self.analyst)
        resp = self.client.post(self._redo_url(case))
        self.assertEqual(resp.status_code, 409)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)

    @patch("api.views.investigations.dispatch_case_analysis")
    def test_finalized_case_dispatches_and_resets(self, mock_dispatch):
        case = self._make_case(LifecycleState.FINALIZED)
        case.results = Result.DANGEROUS
        case.score = 9
        case.final_score = 9
        case.description = "old verdict"
        case.save()

        self.client.force_authenticate(self.analyst)
        resp = self.client.post(self._redo_url(case))

        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.data["dispatched"], 1)

        mock_dispatch.delay.assert_called_once()
        called_case_id, called_intents = mock_dispatch.delay.call_args[0]
        self.assertEqual(called_case_id, case.id)
        self.assertEqual(called_intents, [("url_process.url", self.url.id, "url")])

        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
        self.assertEqual(case.results, Result.INCONCLUSIVE)
        self.assertEqual(case.score, 0)
        self.assertEqual(case.final_score, 0)
        self.assertEqual(case.description, "")

    @patch("api.views.investigations.dispatch_case_analysis")
    def test_contested_case_can_redo(self, mock_dispatch):
        case = self._make_case(LifecycleState.CONTESTED)
        self.client.force_authenticate(self.analyst)
        resp = self.client.post(self._redo_url(case))
        self.assertEqual(resp.status_code, 202)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)

    def test_case_with_no_targets_returns_400(self):
        case = Case.objects.create(
            reporter=self.reporter, description="", lifecycle_state=LifecycleState.FINALIZED,
        )
        self.client.force_authenticate(self.analyst)
        resp = self.client.post(self._redo_url(case))
        self.assertEqual(resp.status_code, 400)

    @patch("api.views.investigations.dispatch_case_analysis")
    def test_old_analyzer_reports_are_not_deleted(self, mock_dispatch):
        case = self._make_case(LifecycleState.FINALIZED)
        analyzer = Analyzer.objects.create(name="YARA", analyzer_cortex_id="yara-1")
        AnalyzerReport.objects.create(
            cortex_job_id="job-1", type="url", status="Success", analyzer=analyzer,
            url=self.url, level="info", confidence=1, score=1,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        self.client.force_authenticate(self.analyst)
        self.client.post(self._redo_url(case))
        self.assertEqual(AnalyzerReport.objects.count(), 1)
