"""The ai_model provider writes what the Cortex AI path wrote, for real Cortex AI reports.

cortex_ai_report.json holds one real, sanitised AnalyzerReport (report_summary + report_full)
per class (SAFE, UNWANTED, DANGEROUS), values stored as strings exactly as Cortex returns them.
The legacy side is the real AiMailParser plus CortexJobManager.manage_ai_jobs; the new side is
result_from_server plus finish_provider_analysis, run against two otherwise identical cases.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from django.test import TestCase

from ai_model.models import AiAssessment
from case_handler.models import Case
from connectors.contrib.ai_model.connector import result_from_server
from connectors.providers import finish_provider_analysis
from connectors.tests.test_provider_dispatch import ai_name, make_mail_case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "cortex_ai_report.json").read_text())
CASE_FIELDS = ("results_ai", "score_ai", "confidence_ai", "category_ai")


def server_payload_from(full):
    """The /v2 classify answer for the report ``full``, built like inference_server/v2.py
    builds it from the legacy classifier dict (full is that dict, as Cortex stored it)."""
    return {
        "results": {"active": {
            "version": "v0",
            "class": full["classification"],
            "score": float(full["malscore"]),
            "confidence": float(full["confidence"]),
            "probabilities": full["classification_breakdown"],
            "sub_class": full["sub_classification"],
            "sub_class_confidence": float(full["sub_classification_confidence"]),
            "sub_probabilities": full["sub_classification_breakdown"],
            "contributing_phrases": full["contributing_phrases"],
            "tier": None,
            "similar_cases": [],
        }},
        "campaign_embedding": "[0.1, 0.2]",  # not part of a Cortex report
        "campaign_embedding_version": "cmp-e1",
        "latency_ms": 12,
    }


def legacy_parse(fx):
    return AiMailParser(analyzer_name=ai_name(), data="mail.tar.gz").parse(fx["summary"], fx["full"])


class FixtureTest(TestCase):
    def test_fixture_covers_every_class_the_model_accepts_but_inconclusive(self):
        self.assertEqual(set(FIXTURE), {"SAFE", "UNWANTED", "DANGEROUS"})
        for klass, fx in FIXTURE.items():
            self.assertEqual(fx["summary"]["classification"], klass)
            self.assertIn(klass, AiAssessment.Result.values)
        self.assertEqual(set(AiAssessment.Result.values) - set(FIXTURE), {"INCONCLUSIVE"})


class ParserParityTest(TestCase):
    def test_provider_mapping_equals_the_legacy_parser_and_sub_class(self):
        for klass, fx in FIXTURE.items():
            with self.subTest(klass):
                legacy = legacy_parse(fx)
                new = result_from_server(server_payload_from(fx["full"]))
                self.assertEqual(
                    (new.result.lower(), new.score, new.confidence),
                    (legacy.level, legacy.score, legacy.confidence),
                )
                self.assertEqual(
                    new.category,
                    CortexJobManager().get_sub_class(SimpleNamespace(report_full=fx["full"])),
                )
                max_length = Case._meta.get_field("category_ai").max_length
                self.assertEqual(
                    new.category, str(fx["full"]["sub_classification"]).capitalize()[:max_length]
                )


class CaseFieldParityTest(TestCase):
    def setUp(self):
        self.analyzer = Analyzer.objects.create(name=ai_name(), analyzer_cortex_id="cx-ai")

    def legacy_case(self, n, fx):
        """A case whose AI fields were written by the real manage_ai_jobs from a Cortex report."""
        case, archive = make_mail_case(n)
        parsed = legacy_parse(fx)  # reports.create_and_save_report stores these on the report
        AnalyzerReport.objects.create(
            cortex_job_id=f"cx-ai-{n}", type="file", status="Success", analyzer=self.analyzer,
            file=archive.archive, level=parsed.level, confidence=parsed.confidence,
            score=parsed.score, report_summary=fx["summary"], report_full=fx["full"],
            report_taxonomy={},
        )
        CortexJobManager().manage_ai_jobs(case)
        case.refresh_from_db()
        return case

    def provider_case(self, n, fx):
        """A case whose AI fields were written by finish_provider_analysis from the /v2 answer."""
        case, _ = make_mail_case(n)
        job = CaseAnalyzerJob.objects.create(
            case=case, cortex_job_id=f"provider-{n}", analyzer=self.analyzer,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        result = result_from_server(server_payload_from(fx["full"]))
        self.assertTrue(finish_provider_analysis(job.id, result, connector="ai_model"))
        case.refresh_from_db()
        return case

    def test_provider_writes_the_case_fields_the_cortex_path_wrote(self):
        for i, (klass, fx) in enumerate(FIXTURE.items()):
            with self.subTest(klass):
                legacy = self.legacy_case(2 * i + 1, fx)
                new = self.provider_case(2 * i + 2, fx)
                self.assertEqual(
                    [getattr(new, f) for f in CASE_FIELDS],
                    [getattr(legacy, f) for f in CASE_FIELDS],
                )
                # And they are not just the model defaults.
                self.assertEqual(new.results_ai, klass.capitalize())

    def test_assessment_keeps_the_same_numbers_and_the_server_answer(self):
        for i, (klass, fx) in enumerate(FIXTURE.items()):
            with self.subTest(klass):
                legacy = legacy_parse(fx)
                case = self.provider_case(i + 1, fx)
                a = AiAssessment.objects.get(case=case)
                self.assertEqual(
                    (a.result, a.score, a.confidence, a.sub_class, a.model_version),
                    (klass, legacy.score, legacy.confidence, fx["full"]["sub_classification"], "v0"),
                )
                self.assertEqual(a.probabilities, fx["full"]["classification_breakdown"])
                self.assertEqual(a.sub_probabilities, fx["full"]["sub_classification_breakdown"])
                self.assertEqual(a.contributing_phrases, fx["full"]["contributing_phrases"])
