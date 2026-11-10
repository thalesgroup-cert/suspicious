from datetime import datetime, timezone as tz

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIRequestFactory

from api.tests.test_report_facts import VT_HASH, VT_IP
from api.utils.case_report_model import build_block, build_case_report
from case_handler.models import (
    Case, CaseHasFileOrMail, ObservableGroup, ObservableGroupArtifact,
)
from cortex_job.models import Analyzer, AnalyzerReport
from domain_process.models import Domain
from email_process.models import MailAddress
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import (
    ArtifactIsIp, ArtifactIsMailAddress, ArtifactIsUrl, Mail, MailArtifact, MailHeader,
)
from url_process.models import URL

NOW = datetime(2026, 11, 10, tzinfo=tz.utc)


class Base(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("rep", "", "x")
        self.request = APIRequestFactory().get("/")
        self.request.user = self.user
        self.vt = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        self.n = 0

    def rep(self, analyzer, level="malicious", status="Success", full=None, enrichment=None, **target):
        self.n += 1
        return AnalyzerReport.objects.create(
            cortex_job_id=f"j{self.n}", type=next(iter(target)), status=status, analyzer=analyzer,
            level=level, confidence=90, score=9, report_summary={}, report_taxonomy={},
            report_full=full or {}, enrichment=enrichment or {}, **target)

    def group_case(self):
        g = ObservableGroup.objects.create()
        return g, Case.objects.create(description="d", reporter=self.user, observable_group=g, results="Dangerous")

    def add_ip(self, g, addr):
        ip = IP.objects.create(address=addr)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        return ip


class GroupTests(Base):
    def test_group_blocks_are_ordered_and_typed(self):
        g, case = self.group_case()
        ip = self.add_ip(g, "203.0.113.7")
        self.rep(self.vt, "malicious", full=VT_IP, enrichment={"source": "virustotal", "malicious_count": 42, "total": 70}, ip=ip)
        d = Domain.objects.create(value="safe.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="DOMAIN", domain=d)
        self.rep(self.vt, "safe", domain=d)
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual(rep.kind, "group")
        self.assertEqual([(b.type, b.value, b.band) for b in rep.blocks],
                         [("ip", "203.0.113.7", "Dangerous"), ("domain", "safe.test", "Safe")])
        self.assertEqual(rep.blocks[0].connectors[0].label, "42/70 detections")
        self.assertEqual([x.title for x in rep.blocks[0].details], ["Location", "VirusTotal"])
        self.assertEqual(rep.rows, [])

    def test_indicator_with_every_source_failed(self):
        g, case = self.group_case()
        ip = self.add_ip(g, "203.0.113.8")
        other = Analyzer.objects.create(name="Shodan", analyzer_cortex_id="sh", tier=2)
        self.rep(self.vt, status="Failure", ip=ip)
        self.rep(other, status="Failure", ip=ip)
        b = build_case_report(case, self.request, now=NOW).blocks[0]
        self.assertEqual(b.band, "Inconclusive")
        self.assertEqual({(l.icon, l.label) for l in b.connectors}, {("⚪", "failed")})
        self.assertEqual((b.details, b.findings), ([], []))

    def test_more_than_ten_group_indicators_get_a_table(self):
        g, case = self.group_case()
        for i in range(12):
            self.add_ip(g, f"198.51.100.{i + 1}")
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual((len(rep.blocks), len(rep.rows), rep.more), (10, 12, 2))

    def test_query_count_does_not_grow_with_indicators(self):
        def queries(n):
            g, case = self.group_case()
            for i in range(n):
                ip = self.add_ip(g, f"198.51.100.{n * 20 + i}")
                self.rep(self.vt, "malicious", ip=ip)
                self.rep(Analyzer.objects.get_or_create(name="Shodan", analyzer_cortex_id="sh", tier=2)[0], "safe", ip=ip)
            with CaptureQueriesContext(connection) as ctx:
                build_case_report(case, self.request, now=NOW)
            return len(ctx)
        self.assertEqual(queries(1), queries(6))

    def test_header_fields(self):
        g, case = self.group_case()
        case.final_confidence = 82.0
        case.verdict_explanation = {"analyst_paragraph": "The address is a known C2 host.",
                                    "confidence_reading": "High confidence: 2 of 3 sources agree."}
        case.save()
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual(rep.generated, "2026-11-10T00:00:00Z")
        self.assertEqual(rep.confidence, "82%")
        self.assertEqual(rep.why, ["The address is a known C2 host.", "High confidence: 2 of 3 sources agree."])

    def test_vt_link_outside_virustotal_is_dropped(self):
        row = {"type": "ip", "value": "203.0.113.7", "verdict": None, "derived_from": None, "sources": [{
            "name": "VirusTotal_GetReport_3_1", "tier": 1, "verdict": "malicious", "failed": False,
            "enrichment": {"source": "virustotal", "vt_link": "javascript:alert(1)", "link": "javascript:alert(1)"},
            "report": VT_IP}]}
        b = build_block(row, now=NOW)
        self.assertEqual(b.vt_link, "https://www.virustotal.com/gui/ip-address/203.0.113.7")


class MailFileTests(Base):
    def test_mail_case_blocks_only_flagged_non_address_indicators(self):
        header = MailHeader.objects.create(header_value="h", fuzzy_hash="f")
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test", date=NOW, to="a@x.test", mail_id="m1", mail_header=header)
        url, ip, addr = URL.objects.create(address="https://evil.test/x"), IP.objects.create(address="203.0.113.9"), MailAddress.objects.create(address="bad@evil.test")
        for t, attr, cls, f, o in (("URL", "artifactIsUrl", ArtifactIsUrl, "url", url), ("IP", "artifactIsIp", ArtifactIsIp, "ip", ip),
                                   ("MailAddress", "artifactIsMailAddress", ArtifactIsMailAddress, "mail_address", addr)):
            ma = MailArtifact.objects.create(mail=mail, artifact_type=t)
            setattr(ma, attr, cls.objects.create(artifact=ma, **{f: o}))
            ma.save(update_fields=[attr])
        self.rep(self.vt, "malicious", url=url)
        self.rep(self.vt, "safe", ip=ip)
        self.rep(self.vt, "malicious", mail=addr)
        hdr = Analyzer.objects.create(name="Mail_Header_Analyzer", analyzer_cortex_id="mh", tier=2)
        aim = Analyzer.objects.create(name="AI_Mail_Analyzer", analyzer_cortex_id="ai", tier=2)
        h = Hash.objects.create(value="a" * 64)
        f = File.objects.create(linked_hash=h, file_path="x.bin", tmp_path="", other_names="")
        self.rep(hdr, "safe", mail_header=header)
        self.rep(aim, "malicious", file=f)
        cf = CaseHasFileOrMail.objects.create(case=Case.objects.create(description="d", reporter=self.user), mail=mail)
        case = cf.case
        case.fileOrMail = cf
        case.save()
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual(rep.kind, "mail")
        self.assertEqual([b.value for b in rep.blocks], ["https://evil.test/x"])
        self.assertEqual({r.type for r in rep.rows}, {"url", "ip", "mail"})
        self.assertIn("Mail_Header_Analyzer", [l.name for l in rep.case_connectors])
        self.assertNotIn("AI_Mail_Analyzer", [l.name for l in rep.case_connectors])

    def test_file_case_has_a_case_analysis_block(self):
        h = Hash.objects.create(value="b" * 64)
        f = File.objects.create(linked_hash=h, file_path="x.bin", tmp_path="", other_names="")
        self.rep(self.vt, "malicious", full=VT_HASH, hash=h)
        case = Case.objects.create(description="d", reporter=self.user, results="Dangerous")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, file=f)
        case.save()
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual((rep.kind, rep.case_analysis.type, rep.case_analysis.value), ("file", "file", h.value))
        self.assertEqual([g.title for g in rep.case_analysis.details], ["Hash", "VirusTotal"])
        self.assertEqual(rep.blocks, [])
