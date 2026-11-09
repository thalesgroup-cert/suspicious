"""The ai_model provider writes what the Cortex AI path wrote, for real Cortex AI reports.

cortex_ai_report.json holds one real, sanitised AnalyzerReport (report_summary + report_full)
per class (SAFE, UNWANTED, DANGEROUS), values stored as strings exactly as Cortex returns them.
The new side is result_from_server plus finish_provider_analysis; the legacy side is frozen
in CORTEX_CASE_FIELDS.
"""
import json
from pathlib import Path

from django.test import TestCase

from ai_model.models import AiAssessment
from connectors.contrib.ai_model.connector import result_from_server
from connectors.providers import finish_provider_analysis
from connectors.tests.test_provider_dispatch import ai_name, make_mail_case
from cortex_job.models import Analyzer, CaseAnalyzerJob

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "cortex_ai_report.json").read_text())
CASE_FIELDS = ("results_ai", "score_ai", "confidence_ai", "category_ai")
# Produced by the removed Cortex AI path (AiMailParser plus its case-field write) from
# cortex_ai_report.json, by running it once before it was deleted.
CORTEX_CASE_FIELDS = {
    "DANGEROUS": ("Dangerous", 10, 96, "Clone"),
    "SAFE": ("Safe", 0, 99, "External"),
    "UNWANTED": ("Unwanted", 5, 56, "Newsletter"),
}


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


class FixtureTest(TestCase):
    def test_fixture_covers_every_class_the_model_accepts_but_inconclusive(self):
        self.assertEqual(set(FIXTURE), {"SAFE", "UNWANTED", "DANGEROUS"})
        for klass, fx in FIXTURE.items():
            self.assertEqual(fx["summary"]["classification"], klass)
            self.assertIn(klass, AiAssessment.Result.values)
        self.assertEqual(set(AiAssessment.Result.values) - set(FIXTURE), {"INCONCLUSIVE"})
        self.assertEqual(set(CORTEX_CASE_FIELDS), set(FIXTURE))


class ParserParityTest(TestCase):
    def test_provider_mapping_equals_what_the_cortex_path_wrote(self):
        for klass, fx in FIXTURE.items():
            with self.subTest(klass):
                new = result_from_server(server_payload_from(fx["full"]))
                self.assertEqual(
                    (new.result.capitalize(), new.score, new.confidence, new.category),
                    CORTEX_CASE_FIELDS[klass],
                )


class CaseFieldParityTest(TestCase):
    def setUp(self):
        self.analyzer = Analyzer.objects.create(name=ai_name(), analyzer_cortex_id="cx-ai")

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
                new = self.provider_case(i + 1, fx)
                self.assertEqual(
                    tuple(getattr(new, f) for f in CASE_FIELDS), CORTEX_CASE_FIELDS[klass]
                )

    def test_assessment_keeps_the_same_numbers_and_the_server_answer(self):
        for i, (klass, fx) in enumerate(FIXTURE.items()):
            with self.subTest(klass):
                _, score, confidence, _ = CORTEX_CASE_FIELDS[klass]
                case = self.provider_case(i + 1, fx)
                a = AiAssessment.objects.get(case=case)
                self.assertEqual(
                    (a.result, a.score, a.confidence, a.sub_class, a.model_version),
                    (klass, score, confidence, fx["full"]["sub_classification"], "v0"),
                )
                self.assertEqual(a.probabilities, fx["full"]["classification_breakdown"])
                self.assertEqual(a.sub_probabilities, fx["full"]["sub_classification_breakdown"])
                self.assertEqual(a.contributing_phrases, fx["full"]["contributing_phrases"])
