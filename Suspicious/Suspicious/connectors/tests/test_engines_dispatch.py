"""connectors.engines: the analyzer selection policy and dispatch (rows written as run_analyzer)."""
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.forms.models import model_to_dict
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import (
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    Connector,
    ConnectorManifest,
    FETCH_RESULT,
    FETCH_UNKNOWN,
    FetchResult,
    HealthStatus,
    StartResult,
)
from connectors.contrib.cortex.connector import CortexConnector
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from mail_feeder.models import MailHeader
from url_process.models import URL

ROLES = {"yara": "Yara", "file_info": "FileInfo", "sandbox": "Sandbox", "header": "Header", "ai": "AI"}
NO_AI = {"header": "Header", "yara": "Yara", "sandbox": None, "file_info": "FileInfo"}


def e(name, *types):
    return CatalogEntry(id=f"id-{name}", name=name, data_types=types or ("url",))


def names(entries):
    return [x.name for x in entries]


def a_file(name):
    return SimpleNamespace(file_path=SimpleNamespace(name=name))


class SelectAnalyzersTest(SimpleTestCase):
    ALL = [e(n) for n in ("Yara", "FileInfo", "Sandbox", "Header", "AI", "VT")]

    def select(self, data_type, value=None, roles=ROLES):
        return names(engines.select_analyzers(data_type, value, self.ALL, roles))

    def test_mail_body_is_only_yara(self):
        self.assertEqual(self.select("mail_body", "/tmp/x.txt"), ["Yara"])

    def test_mail_header_is_only_header(self):
        self.assertEqual(self.select("mail_header"), ["Header"])

    def test_mail_header_without_header_role_is_empty(self):
        roles = {k: v for k, v in ROLES.items() if k != "header"}
        self.assertEqual(self.select("mail_header", roles=roles), [])

    def test_file_is_yara_file_info_sandbox(self):
        self.assertEqual(self.select("file", a_file("x.pdf")), ["Yara", "FileInfo", "Sandbox"])

    def test_eml_file_drops_ai_yara_sandbox_header(self):
        self.assertEqual(self.select("file", a_file("mail.eml")), ["FileInfo"])

    def test_eml_file_with_absent_ai_and_none_sandbox(self):
        # An absent role must never put None or {} into a set (an earlier bug).
        self.assertEqual(self.select("file", a_file("mail.eml"), NO_AI), ["FileInfo"])

    def test_file_without_file_path_raises(self):
        with self.assertRaises(TypeError):
            engines.select_analyzers("file", SimpleNamespace(), self.ALL, ROLES)

    def test_other_types_drop_yara_sandbox_header(self):
        for data_type in ("url", "ip", "domain", "hash", "mail"):
            self.assertEqual(self.select(data_type), ["FileInfo", "AI", "VT"], data_type)

    def test_absent_roles(self):
        self.assertEqual(self.select("url", roles={}), names(self.ALL))
        self.assertEqual(self.select("file", a_file("x.pdf"), roles={}), [])
        self.assertEqual(self.select("mail_body", "/tmp/x", roles={}), [])
        self.assertEqual(self.select("url", roles={"yara": None, "sandbox": ""}), names(self.ALL))


class LedgerIdsTest(SimpleTestCase):
    def test_cortex_is_raw(self):
        self.assertEqual(engines.ledger_ids("cortex", "job1", "an1"), ("job1", "an1"))

    def test_other_is_namespaced(self):
        job, analyzer = engines.ledger_ids("fake", "job1", "an1")
        self.assertEqual((job, analyzer), ("fake-job1", "fake:an1"))
        self.assertLessEqual(max(len(job), len(analyzer)), 50)

    def test_too_long_raises(self):
        with self.assertRaises(ValueError):
            engines.ledger_ids("fake", "j" * 50, "a")


def make_engine(engine_name):
    class Fake(Connector):
        manifest = ConnectorManifest(name=engine_name, version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
        offered: list = []
        started: list = []
        refuse: set = set()
        raise_on: set = set()
        catalog_error = None

        def health_check(self):
            return HealthStatus(ok=True)

        def catalog(self, data_type=None, name=None):
            if type(self).catalog_error:
                raise type(self).catalog_error
            return [x for x in type(self).offered
                    if (name and x.name == name) or (data_type and data_type in x.data_types)]

        def start(self, analyzer, data_type, value):
            if analyzer.name in type(self).raise_on:
                raise ConnectionError("http://user:pw@engine.example/api")
            if analyzer.name in type(self).refuse:
                return None
            type(self).started.append((analyzer.name, data_type, value))
            return StartResult(job_id=f"job-{analyzer.name}")

    return Fake


CONFIGS = {
    "integrations.cortex": {"url": "http://cortex:9001", "api_key": "k", "analyzers": ROLES},
}


class DispatchTest(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fake_a, self.fake_b = make_engine("fake_a"), make_engine("fake_b")
        self.registry = ConnectorRegistry()
        for cls in (self.fake_a, self.fake_b, CortexConnector):
            self.registry.register(cls)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: CONFIGS.get(n, {}))
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, on in (("fake_a", True), ("fake_b", True), ("cortex", False)):
            ConnectorState.objects.create(name=name, enabled=on)
        user = get_user_model().objects.create_user(username="engines", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=user)
        self.case2 = Case.objects.create(status="On Going", description="", reporter=user)
        self.url = URL.objects.create(address="http://phish.example/login")

    def only(self, *enabled):
        ConnectorState.objects.update(enabled=False)
        ConnectorState.objects.filter(name__in=enabled).update(enabled=True)

    def test_enabled_engines_sorted(self):
        self.assertEqual(engines.enabled_engines(), ["fake_a", "fake_b"])

    def test_row_parity_with_run_analyzer_through_cortex(self):
        self.only("cortex")
        vt = SimpleNamespace(id="vt1", name="VT", dataTypeList=["url"])
        with mock.patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi") as api_cls:
            api = api_cls.return_value
            api.analyzers.get_by_type.return_value = [vt]
            api.analyzers.run_by_name.side_effect = [SimpleNamespace(id="j1"), SimpleNamespace(id="j2")]
            CortexJob.run_analyzer(api, vt, self.url, "url", self.case)
            ids = engines.dispatch(self.url, "url", self.case2)
        self.assertEqual(ids, ["j2"])
        first, second = api.analyzers.run_by_name.call_args_list
        self.assertEqual(first, second)
        self.assertEqual(second.args[1], {"data": self.url.address, "dataType": "url", "tlp": 2})
        skip = ("id", "cortex_job_id")
        old, new = (model_to_dict(AnalyzerReport.objects.get(cortex_job_id=j), exclude=skip)
                    for j in ("j1", "j2"))
        self.assertEqual(old, new)
        self.assertEqual(
            (new["status"], new["level"], new["confidence"], new["score"], new["report_summary"],
             new["report_full"], new["report_taxonomy"], new["url"], new["type"]),
            ("InProgress", "info", 0, 0, {"ongoing": "analysis"}, {"ongoing": "analysis"},
             {"ongoing": "analysis"}, self.url.id, "url"),
        )
        caj = CaseAnalyzerJob.objects.get(case=self.case2)
        old_caj = CaseAnalyzerJob.objects.get(case=self.case)
        self.assertEqual((caj.cortex_job_id, caj.status), ("j2", CaseAnalyzerJob.STATUS_INPROGRESS))
        self.assertEqual((caj.analyzer_id, caj.status), (old_caj.analyzer_id, old_caj.status))
        self.assertEqual(caj.analyzer_report.cortex_job_id, "j2")
        self.assertEqual(Analyzer.objects.get().analyzer_cortex_id, "vt1")

    def test_fake_engine_rows_are_namespaced(self):
        self.only("fake_a")
        self.fake_a.offered = [e("VT")]
        ids = engines.dispatch(self.url, "url", self.case)
        self.assertEqual(ids, ["fake_a-job-VT"])
        self.assertEqual(self.fake_a.started, [("VT", "url", self.url.address)])
        analyzer = Analyzer.objects.get(name="VT")
        self.assertEqual((analyzer.analyzer_cortex_id, analyzer.source), ("fake_a:id-VT", "fake_a"))
        ar = AnalyzerReport.objects.get()
        self.assertEqual((ar.cortex_job_id, ar.status, ar.url_id), ("fake_a-job-VT", "InProgress", self.url.id))
        caj = CaseAnalyzerJob.objects.get()
        self.assertEqual((caj.cortex_job_id, caj.analyzer_report_id, caj.status),
                         ("fake_a-job-VT", ar.id, CaseAnalyzerJob.STATUS_INPROGRESS))

    def test_dispatch_creates_the_analyzer_row_with_weight_and_tier(self):
        from cortex_job.migrations._tier_seed import tier_for
        self.only("fake_a")
        self.fake_a.offered = [e("VirusTotal_GetReport_3_1")]
        engines.dispatch(self.url, "url", self.case)
        row = Analyzer.objects.get()
        self.assertEqual((row.weight, row.tier), (0.2, tier_for("VirusTotal_GetReport_3_1")))
        self.assertEqual(CaseAnalyzerJob.objects.get().analyzer, row)

    def test_too_long_id_is_not_started(self):
        self.only("fake_a")
        self.fake_a.offered = [CatalogEntry("x" * 50, "Long", ("url",)), e("Ok")]
        with self.assertLogs("connectors.engines", "ERROR"):
            self.assertEqual(engines.dispatch(self.url, "url", self.case), ["fake_a-job-Ok"])
        self.assertEqual([n for n, *_ in self.fake_a.started], ["Ok"])
        self.assertEqual(
            list(ConnectorDelivery.objects.filter(status="failed").values_list("error", flat=True)),
            ["Long: id too long"])

    def test_unreadable_roles_are_empty(self):
        self.only("fake_a")
        self.fake_a.offered = [e("Yara"), e("VT")]
        def get_section(name):
            if name == "integrations.cortex":
                raise RuntimeError("db down")
            return {}

        with mock.patch("settings.config.get_section", side_effect=get_section), \
                self.assertLogs("connectors.engines", "ERROR"):
            ids = engines.dispatch(self.url, "url", self.case)
        self.assertEqual(sorted(ids), ["fake_a-job-VT", "fake_a-job-Yara"])

    def test_dispatch_never_raises(self):
        with mock.patch("connectors.engines.enabled_engines", side_effect=RuntimeError("db")), \
                self.assertLogs("connectors.engines", "ERROR"):
            self.assertEqual(engines.dispatch(self.url, "url", self.case), [])

    def test_two_engines_one_raising(self):
        self.fake_a.offered, self.fake_b.offered = [e("VT_A")], [e("VT_B")]
        self.assertEqual(len(engines.dispatch(self.url, "url", self.case)), 2)
        self.assertEqual(CaseAnalyzerJob.objects.filter(case=self.case).count(), 2)
        self.fake_a.catalog_error = RuntimeError("down")
        self.assertEqual(engines.dispatch(self.url, "url", self.case2), ["fake_b-job-VT_B"])

    def test_refused_and_raising_starts_do_not_stop_the_others(self):
        self.only("fake_a")
        self.fake_a.offered = [e("Refused"), e("Boom"), e("Ok")]
        self.fake_a.refuse, self.fake_a.raise_on = {"Refused"}, {"Boom"}
        self.assertEqual(engines.dispatch(self.url, "url", self.case), ["fake_a-job-Ok"])
        self.assertEqual(list(AnalyzerReport.objects.values_list("analyzer__name", flat=True)), ["Ok"])
        failed = ConnectorDelivery.objects.filter(connector="fake_a", event="start", status="failed")
        # A refusal is routine: no ledger row. Only the raising start is a failed delivery.
        self.assertEqual(list(failed.values_list("error", flat=True)), ["Boom: ConnectionError"])
        self.assertEqual(set(failed.values_list("case_id", flat=True)), {self.case.id})

    def test_disabled_engine_starts_nothing(self):
        self.only("fake_b")
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])

    def test_no_engine_enabled_writes_nothing(self):
        self.only()
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertFalse(AnalyzerReport.objects.exists())
        self.assertFalse(CaseAnalyzerJob.objects.exists())
        self.assertFalse(ConnectorDelivery.objects.exists())

    def test_no_engine_enabled_logs_one_warning_without_the_value(self):
        self.only()
        with self.assertLogs("connectors.engines", "DEBUG") as logs:
            engines.dispatch(self.url, "url", self.case)
        self.assertEqual(logs.output, [
            f"WARNING:connectors.engines:no analysis engine enabled; url on case {self.case.id} not analysed"])

    def test_name_owned_by_another_source_is_skipped(self):
        self.only("fake_a")
        Analyzer.objects.create(name="VT", analyzer_cortex_id="vt1", source="cortex")
        self.fake_a.offered = [e("VT")]
        with self.assertLogs("connectors.engines", "ERROR"):
            self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])
        self.assertFalse(AnalyzerReport.objects.exists())

    def test_case_required(self):
        with self.assertRaises(TypeError):
            engines.dispatch(self.url, "url", None)

    def test_empty_value_starts_nothing(self):
        self.only("fake_a")
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(URL.objects.create(address="  "), "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])

    def test_role_types_look_roles_up_by_name(self):
        self.only("fake_a")
        self.fake_a.offered = [e("Header", "other"), e("Yara", "other")]
        header = MailHeader.objects.create(header_value="From: a@b", fuzzy_hash="fh")
        self.assertEqual(engines.dispatch(header, "mail_header", self.case), ["fake_a-job-Header"])
        self.assertEqual(AnalyzerReport.objects.get().mail_header, header)

    def test_launch_cortex_jobs_forwards(self):
        with mock.patch("connectors.engines.dispatch", return_value=["x"]) as dispatch, \
                mock.patch("cortex_job.cortex_utils.cortex_and_job_management.SessionCortexApi") as api:
            self.assertEqual(CortexJob().launch_cortex_jobs(self.url, "url", self.case), ["x"])
        dispatch.assert_called_once_with(self.url, "url", self.case)
        api.assert_not_called()


SCORE = "connectors.engines._score"


class FinishedStartRulesTest(TestCase):
    """A start that returns a finished result obeys the rules refresh applies."""

    def setUp(self):
        self.fake = make_engine("fake_a")
        self.registry = ConnectorRegistry()
        self.registry.register(self.fake)
        patcher = mock.patch("connectors.engines.registry", self.registry)
        patcher.start()
        self.addCleanup(patcher.stop)
        user = get_user_model().objects.create_user(username="fin", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=user)
        self.url = URL.objects.create(address="http://phish.example/login")

    def start(self, finished, data_type="url", value=None):
        connector = mock.Mock()
        connector.start.return_value = StartResult(job_id="j1", finished=finished)
        with mock.patch(SCORE) as score:
            engines._start(connector, "fake_a", e("VT"), value or self.url, data_type,
                           value or self.url.address, self.case)
        return score, AnalyzerReport.objects.get(), CaseAnalyzerJob.objects.get()

    def result(self, status="Success", **kw):
        return FetchResult(FETCH_RESULT, status, **kw)

    def test_body_is_stored_and_row_closed(self):
        summary = {"taxonomies": [{"level": "info"}]}
        score, report, caj = self.start(self.result(summary=summary, full={"a": 1}))
        self.assertEqual((report.status, report.report_summary, report.report_taxonomy, report.report_full),
                         ("Success", summary, summary["taxonomies"], {"a": 1}))
        self.assertEqual(caj.status, "Success")
        self.assertIsNotNone(caj.completed_at)
        score.assert_called_once()

    def test_non_result_finished_start_writes_nothing(self):
        score, report, caj = self.start(FetchResult(FETCH_UNKNOWN))
        self.assertEqual((report.status, report.report_summary), ("InProgress", {"ongoing": "analysis"}))
        self.assertEqual(caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)
        score.assert_not_called()

    def test_success_without_body_stays_pending_and_scores(self):
        score, report, caj = self.start(self.result())
        self.assertEqual(report.status, "InProgress")
        self.assertEqual(caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)
        self.assertIsNone(caj.completed_at)
        score.assert_called_once()

    def test_data_type_mismatch_writes_nothing_and_warns(self):
        with self.assertLogs("connectors.engines", "WARNING") as logs:
            score, report, caj = self.start(self.result(summary={"x": 1}, data_type="ip"))
        self.assertEqual((report.status, report.report_summary), ("InProgress", {"ongoing": "analysis"}))
        self.assertEqual(caj.status, CaseAnalyzerJob.STATUS_INPROGRESS)
        self.assertIsNone(caj.completed_at)
        self.assertIn("VT", logs.output[0])
        self.assertIn("ip", logs.output[0])
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_mail_body_accepts_file(self):
        score, report, caj = self.start(
            self.result(summary={"x": 1}, data_type="file"), "mail_body", "/tmp/abc.txt")
        self.assertEqual((report.status, caj.status), ("Success", "Success"))

    def test_failure_without_body_closes_the_row(self):
        score, report, caj = self.start(self.result("Failure"))
        self.assertEqual((report.status, caj.status), ("Failure", "Failure"))
        self.assertIsNotNone(caj.completed_at)
        score.assert_not_called()
