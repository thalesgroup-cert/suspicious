from types import SimpleNamespace as NS

from django.test import SimpleTestCase, TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.classification import derive_threat_classification
from score_process.scoring.health import analysis_health


def _rep(category=None, label=None, confidence=50):
    enrichment = {k: v for k, v in (("threat_category", category), ("threat_label", label)) if v}
    return NS(enrichment=enrichment or None, confidence=confidence)


class ThreatClassificationTests(SimpleTestCase):
    def test_mail_case_uses_the_ai_category(self):
        case = NS(category_ai="Classic phishing")
        got = derive_threat_classification(case, [_rep("trojan", "trojan.emotet", 90)])
        self.assertEqual(got, {"label": "Classic phishing", "category": "Classic phishing", "source": "ai"})

    def test_uncategorized_ai_falls_through_to_virustotal(self):
        for ai in ("Uncategorized", "uncategorized", "", None, "Unknown"):
            got = derive_threat_classification(NS(category_ai=ai), [_rep("trojan", "trojan.emotet", 90)])
            self.assertEqual(got["source"], "virustotal", ai)

    def test_virustotal_picks_the_category_with_the_most_confidence(self):
        case = NS(category_ai="Uncategorized")
        reports = [_rep("adware", "adware.x", 20), _rep("trojan", "trojan.emotet", 60), _rep("trojan", "trojan.emotet", 55)]
        self.assertEqual(
            derive_threat_classification(case, reports),
            {"label": "trojan.emotet", "category": "trojan", "source": "virustotal"},
        )

    def test_label_defaults_to_the_category_and_zero_confidence_still_counts(self):
        case = NS(category_ai="Uncategorized")
        self.assertEqual(
            derive_threat_classification(case, [_rep("ransomware", None, 0)]),
            {"label": "ransomware", "category": "ransomware", "source": "virustotal"},
        )

    def test_nothing_known_returns_none(self):
        case = NS(category_ai="Uncategorized")
        self.assertIsNone(derive_threat_classification(case, []))
        self.assertIsNone(derive_threat_classification(case, [_rep(), NS(enrichment="junk", confidence=1)]))


class AnalysisHealthTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.ip = IP.objects.create(address="1.2.3.4")

    def _report(self, name, status, tier=2):
        analyzer, _ = Analyzer.objects.get_or_create(
            name=name, defaults={"analyzer_cortex_id": name.lower(), "tier": tier},
        )
        return AnalyzerReport.objects.create(
            cortex_job_id=f"j-{name}", type="ip", status=status, analyzer=analyzer, ip=self.ip,
            level="info", confidence=1, score=1, report_summary={}, report_taxonomy={}, report_full={},
        )

    def test_counts_and_names_the_failures(self):
        reports = [self._report("VT", "Success"), self._report("Shodan", "Failure"),
                   self._report("Urlscan", "InProgress"), self._report("Gone", "Deleted")]
        health = analysis_health(reports)
        self.assertEqual((health["total"], health["failed"], health["pending"]), (3, 1, 1))
        self.assertEqual(health["failures"], [{"analyzer": "Shodan", "target": "1.2.3.4", "status": "Failure"}])

    def test_all_good_has_no_failures(self):
        health = analysis_health([self._report("VT", "Success")])
        self.assertEqual((health["total"], health["failed"], health["pending"], health["failures"]), (1, 0, 0, []))

    def test_no_reports(self):
        self.assertEqual(analysis_health([]), {"total": 0, "failed": 0, "pending": 0, "failures": []})
