"""ai_model_engine_replay: a read-only sensitivity study of the shadow's AI signal (Plan F, Task 5)."""
import json
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from ai_model import registry
from ai_model.models import ModelEvent, ShadowResult
from ai_model.tests.test_registry import cand
from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from connectors.tests.test_provider_dispatch import make_mail_case

MOD = "ai_model.management.commands.ai_model_engine_replay"
SECRET = "SECRET-BODY"


def answer(klass, score, conf=0.95):
    return {"results": {"shadow": {"class": klass, "score": score, "confidence": conf, "version": "s1"}}}


class FakeClient:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def classify(self, body, exclude_case_ids=None, versions=("active",)):
        self.calls.append((body, exclude_case_ids, list(versions)))
        item = self.answers.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class EngineReplayTest(TestCase):
    n = 0

    def setUp(self):
        self.analyzer = Analyzer.objects.create(name="IpA", analyzer_cortex_id="IpA", weight=1)
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))

    def case(self, live="Safe", score=2):
        type(self).n += 1
        case, _ = make_mail_case(self.n)
        case.results, case.results_ai, case.score_ai, case.confidence_ai = live, live, score, 90
        case.save()
        report = AnalyzerReport.objects.create(
            cortex_job_id=f"r{self.n}", type="ip", status="Success", analyzer=self.analyzer,
            level="safe", confidence=50, score=1, report_summary={}, report_taxonomy={}, report_full={})
        CaseAnalyzerJob.objects.create(case=case, cortex_job_id=f"r{self.n}", analyzer=self.analyzer,
                                       analyzer_report=report, status="Success")
        return case

    def run_cmd(self, client, *args, version="s1"):
        out = StringIO()
        with mock.patch(MOD + ".connector_registry.instantiate") as inst, \
                mock.patch(MOD + ".mail_archive_for", return_value=object()), \
                mock.patch(MOD + ".read_archive_body", return_value=SECRET):
            inst.return_value._client.return_value = client
            call_command("ai_model_engine_replay", version, *args, stdout=out)
        return out.getvalue()

    def test_refuses_a_version_that_is_not_the_shadow(self):
        cand("c2")
        with self.assertRaises(CommandError):
            self.run_cmd(FakeClient([]), version="c2")

    def test_counts_flips_and_writes_nothing(self):
        c1 = self.case("Safe", 2)
        self.case("Dangerous", 9)
        client = FakeClient([answer("DANGEROUS", 9), answer("DANGEROUS", 9)])
        counts = lambda: (Case.objects.count(), ShadowResult.objects.count(), ModelEvent.objects.count())
        before = counts()
        with CaptureQueriesContext(connection) as q:
            data = json.loads(self.run_cmd(client, "--json"))
        self.assertEqual(counts(), before)
        self.assertFalse([x for x in q.captured_queries
                          if x["sql"].lstrip().split(None, 1)[0].upper() in ("INSERT", "UPDATE", "DELETE")])
        self.assertEqual((data["replayed"], data["skipped"], data["changed"], data["critical"]), (2, 0, 1, 1))
        self.assertEqual(data["matrix"], {"Safe->Dangerous": 1, "Dangerous->Dangerous": 1})
        self.assertIn("inconclusive_rate_before", data)
        self.assertIn("median_confidence_after", data)
        self.assertIn([SECRET, [c1.id], ["shadow"]], [list(c) for c in client.calls])

    def test_a_refused_classify_is_skipped_and_text_is_never_printed(self):
        self.case()
        self.case()
        text = self.run_cmd(FakeClient([ValueError("no"), answer("SAFE", 1)]))
        self.assertIn("skipped: 1", text)
        for word in (SECRET, "subject", "@"):
            self.assertNotIn(word, text)

    def test_limit_and_since_days(self):
        old = self.case()
        Case.objects.filter(pk=old.pk).update(creation_date="2020-01-01T00:00:00Z")
        self.case()
        self.case()
        client = FakeClient([answer("SAFE", 1)] * 3)
        data = json.loads(self.run_cmd(client, "--json", "--limit", "1"))
        self.assertEqual(data["replayed"], 1)
        data = json.loads(self.run_cmd(client, "--json", "--since-days", "30"))
        self.assertEqual(data["replayed"], 2)
