"""The platform runs on the fixture engine alone (Cortex disabled) and beside Cortex: real
engines.dispatch and reconcile_case_core, only the registry, config, emit hook and Cortex operations patched."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import FETCH_RESULT, CatalogEntry, FetchResult, StartResult
from connectors.contrib.cortex.connector import CortexConnector
from connectors.contrib.fixture.connector import FixtureEngineConnector
from connectors.models import ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.cortex_utils.case_targets import collect_case_targets
from cortex_job.cortex_utils.reconciliation import reconcile_case_core
from cortex_job.models import AnalyzerReport, CaseAnalyzerJob
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailAttachment, MailBody, MailHeader
from url_process.models import URL

ROLES = {"yara": "Fixture_Yara_1_0", "file_info": "Fixture_FileInfo_1_0",
         "sandbox": "Fixture_Sandbox_1_0", "header": "Fixture_Header_1_0"}
CORTEX_OK = FetchResult(FETCH_RESULT, "Success",
                        {"taxonomies": [{"level": "safe", "namespace": "C", "predicate": "V", "value": "ok"}]},
                        {"results": []}, data_type="url")


class FixturePipelineTest(TestCase):
    confirm = True

    def setUp(self):
        self.config = {
            "integrations.cortex": {"url": "http://cortex:9001", "api_key": "k", "analyzers": dict(ROLES)},
            "integrations.fixture_engine": {"confirm_fixture": self.confirm},
        }
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        registry = ConnectorRegistry()
        registry.register(FixtureEngineConnector)
        registry.register(CortexConnector)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry"):
            patcher = mock.patch(target, registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: dict(self.config.get(n, {})))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")
        self.emit = patcher.start()
        self.addCleanup(patcher.stop)
        self.cx = {
            "catalog": self._patch_cortex("catalog", return_value=[CatalogEntry("cx-url", "Cortex_URL", ("url",))]),
            "start": self._patch_cortex("start", return_value=StartResult("cxjob1")),
            "fetch": self._patch_cortex("fetch", return_value=FetchResult("unknown")),
        }
        ConnectorState.objects.create(name="fixture_engine", enabled=True)
        ConnectorState.objects.create(name="cortex", enabled=False)
        self.user = get_user_model().objects.create_user(username="fx", password="x")

    def _patch_cortex(self, op, **kwargs):
        patcher = mock.patch.object(CortexConnector, op, autospec=False, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _case(self, **links):
        return Case.objects.create(status="On Going", description="", reporter=self.user,
                                   dispatched_at=timezone.now(), **links)

    def url_case(self, address):
        case = self._case()
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=URL.objects.create(address=address))
        case.save(update_fields=["nonFileIocs"])
        return case

    def mail_case(self, header="From: a@good.example", path="report.pdf"):
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
            mail_header=MailHeader.objects.create(header_value=header, fuzzy_hash="h1"),
            mail_body=MailBody.objects.create(body_value="hello", fuzzy_hash="b1"),
        )
        attachment = File.objects.create(linked_hash=Hash.objects.create(value="a" * 64), file_path=path,
                                         tmp_path=path, other_names="")
        MailAttachment.objects.create(mail=mail, file=attachment)
        case = self._case()
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        return case

    def dispatch(self, case):
        for target, data_type in collect_case_targets(case):
            if data_type == "mail_body":  # the submission path hands over the stored body's file path
                target = f"/tmp/{target.fuzzy_hash}.txt"
            engines.dispatch(target, data_type, case)

    def reconcile(self, case):
        reconcile_case_core(case)
        case.refresh_from_db()
        return case

    def jobs(self, case):
        return CaseAnalyzerJob.objects.filter(case=case)

    def names(self, case):
        return sorted(self.jobs(case).values_list("analyzer__name", flat=True))


class FixtureOnlyTest(FixturePipelineTest):
    def assert_closed_by_fixture(self, case):
        self.assertEqual(set(self.jobs(case).values_list("analyzer__source", flat=True)), {"fixture_engine"})
        self.assertFalse(self.jobs(case).filter(status__in=CaseAnalyzerJob.PENDING_STATUSES).exists())
        for job in self.jobs(case):
            self.assertTrue(job.cortex_job_id.startswith("fixture_engine-fixture-"))
            self.assertIsNotNone(job.completed_at)
        for method in self.cx.values():
            method.assert_not_called()

    def test_url_case_with_a_marker_is_malicious(self):
        case = self.url_case("http://evil.example/login")
        self.dispatch(case)
        self.assertEqual(self.names(case), ["Fixture_Reputation_1_0"])
        self.assert_closed_by_fixture(case)
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(case.description, "All analyzers completed successfully. You can now view the full results.")
        self.emit.assert_called_once_with("case_finalised", case)
        self.assertEqual(case.results, "Dangerous")

    def test_clean_url_case_is_safe(self):
        case = self.url_case("http://good.example/")
        self.dispatch(case)
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(case.results, "Safe")

    def test_mail_case_gets_every_role_analyzer_from_the_fixture(self):
        case = self.mail_case()
        self.dispatch(case)
        self.assertEqual(self.names(case), ["Fixture_FileInfo_1_0", "Fixture_Header_1_0",
                                            "Fixture_Sandbox_1_0", "Fixture_Yara_1_0", "Fixture_Yara_1_0"])
        self.assert_closed_by_fixture(case)
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(case.results, "Safe")

    def test_mail_verdict_follows_the_markers(self):
        case = self.mail_case(path="evil/report.pdf")  # a directory component counts
        self.dispatch(case)
        case = self.reconcile(case)
        self.assertEqual(case.results, "Dangerous")
        case = self.mail_case(header="From: ceo@phish.example")
        self.dispatch(case)
        case = self.reconcile(case)
        self.assertEqual(case.results, "Dangerous")


class FixtureUnconfirmedTest(FixturePipelineTest):
    confirm = False

    def test_no_rows_and_the_case_finalises_unanalysed(self):
        case = self.url_case("http://good.example/")
        with self.assertLogs("connectors.contrib.fixture.connector", "WARNING") as logs:
            self.dispatch(case)
        self.assertIn("fixture engine is inert", logs.output[0])
        self.assertEqual(self.jobs(case).count(), 0)
        self.assertFalse(AnalyzerReport.objects.filter(analyzer__source="fixture_engine").exists())
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertTrue(case.description.startswith("No analyzer was applicable"))
        self.assertEqual(case.results, "Failure")

    def test_a_mail_case_is_not_scored_safe_either(self):
        case = self.mail_case()
        self.dispatch(case)
        self.assertEqual(self.jobs(case).count(), 0)
        case = self.reconcile(case)
        self.assertTrue(case.description.startswith("No analyzer was applicable"))


class FixtureBesideCortexTest(FixturePipelineTest):
    def test_both_engines_hold_rows_and_the_case_waits_for_cortex(self):
        ConnectorState.objects.filter(name="cortex").update(enabled=True)
        case = self.url_case("http://evil.example/")
        self.dispatch(case)
        self.assertEqual(self.names(case), ["Cortex_URL", "Fixture_Reputation_1_0"])
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
        self.assertEqual(dict(self.jobs(case).values_list("analyzer__source", "status")),
                         {"fixture_engine": "Success", "cortex": "InProgress"})
        self.cx["fetch"].return_value = CORTEX_OK
        case = self.reconcile(case)
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
