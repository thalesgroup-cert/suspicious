from django.test import TestCase
from django.contrib.auth.models import User

from ip_process.models import IP
from cortex_job.models import Analyzer, AnalyzerReport
from case_handler.models import Case, Result, ObservableGroup, ObservableGroupArtifact
from score_process.scoring.apply import finalise_ioc_group


class IocRoadScoringTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")
        self.gti = Analyzer.objects.create(name="GTI", analyzer_cortex_id="gti1", tier=1, weight=0.9)
        self.abuse = Analyzer.objects.create(name="AbuseIPDB", analyzer_cortex_id="ab1", tier=3, weight=0.2)

    def _case_with_ip(self, address):
        ip = IP.objects.create(address=address)
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="t", reporter=self.user, observable_group=group)
        return case, ip

    def test_tier1_clean_ip_scores_group_safe(self):
        case, ip = self._case_with_ip("8.8.8.8")
        AnalyzerReport.objects.create(cortex_job_id="j1", type="ip", status="Success",
            analyzer=self.gti, ip=ip, level="safe", confidence=95, score=0,
            report_summary={}, report_taxonomy={}, report_full={})
        AnalyzerReport.objects.create(cortex_job_id="j2", type="ip", status="Success",
            analyzer=self.abuse, ip=ip, level="suspicious", confidence=30, score=7,
            report_summary={}, report_taxonomy={}, report_full={})

        finalise_ioc_group(case)

        case.refresh_from_db()
        ip.refresh_from_db()
        self.assertEqual(case.results, Result.SAFE)
        self.assertEqual(ip.ioc_level.lower(), "safe")
        self.assertEqual(case.score, 2)

    def test_tier1_malicious_ip_scores_group_dangerous(self):
        case, ip = self._case_with_ip("1.2.3.4")
        AnalyzerReport.objects.create(cortex_job_id="j3", type="ip", status="Success",
            analyzer=self.gti, ip=ip, level="malicious", confidence=95, score=10,
            report_summary={}, report_taxonomy={}, report_full={})

        finalise_ioc_group(case)

        case.refresh_from_db()
        ip.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(ip.ioc_level.lower(), "malicious")
        self.assertEqual(case.score, 9)

    def test_deny_listed_domain_forces_dangerous_despite_clean_analyzers(self):
        from domain_process.models import Domain
        from settings.models import DenyListDomain

        domain = Domain.objects.create(value="evil-phish.example")
        DenyListDomain.objects.create(domain=domain, user=self.user)
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="DOMAIN", domain=domain
        )
        case = Case.objects.create(description="t", reporter=self.user, observable_group=group)
        AnalyzerReport.objects.create(cortex_job_id="j4", type="domain", status="Success",
            analyzer=self.gti, domain=domain, level="safe", confidence=90, score=0,
            report_summary={}, report_taxonomy={}, report_full={})

        finalise_ioc_group(case)

        case.refresh_from_db()
        domain.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(domain.ioc_level.lower(), "malicious")
