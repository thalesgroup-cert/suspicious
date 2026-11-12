from datetime import datetime, timezone as tz

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIRequestFactory

from api.tests.test_report_facts import VT_DOMAIN, VT_HASH, VT_IP
from ai_model.models import AiAssessment, LabelRecord
from api.utils.case_report_model import build_block, build_case_report
from case_handler.models import (
    Campaign, CampaignMember, Case, CaseHasFileOrMail, ObservableGroup, ObservableGroupArtifact,
)
from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
from connectors.models import ConnectorState
from cortex_job.models import Analyzer, AnalyzerReport
from domain_process.models import Domain
from email_process.models import MailAddress
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import (
    ArtifactIsIp, ArtifactIsMailAddress, ArtifactIsUrl, Mail, MailArtifact, MailAttachment, MailBody,
    MailHeader,
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

    def test_blocks_sort_by_band_then_value_and_no_verdict_last(self):
        g, case = self.group_case()
        safe = self.add_ip(g, "198.51.100.1")
        self.add_ip(g, "198.51.100.2")  # no reports -> no verdict
        inc = self.add_ip(g, "198.51.100.3")
        sus, dan = (Domain.objects.create(value=v) for v in ("aa.test", "zz.test"))
        dan2 = Domain.objects.create(value="bb.test")
        for d in (sus, dan, dan2):
            ObservableGroupArtifact.objects.create(group=g, artifact_type="DOMAIN", domain=d)
        self.rep(self.vt, "safe", ip=safe)
        self.rep(self.vt, "info", status="Failure", ip=inc)
        self.rep(self.vt, "suspicious", domain=sus)
        self.rep(self.vt, "malicious", domain=dan)
        self.rep(self.vt, "malicious", domain=dan2)
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual([(b.value, b.band) for b in rep.blocks], [
            ("bb.test", "Dangerous"), ("zz.test", "Dangerous"), ("aa.test", "Suspicious"),
            ("198.51.100.1", "Safe"), ("198.51.100.3", "Inconclusive"), ("198.51.100.2", None)])

    def test_indicator_with_every_source_failed(self):
        g, case = self.group_case()
        ip = self.add_ip(g, "203.0.113.8")
        other = Analyzer.objects.create(name="Shodan", analyzer_cortex_id="sh", tier=2)
        self.rep(self.vt, status="Failure", full=VT_IP,
                 enrichment={"source": "virustotal", "malicious_count": 42, "total": 70}, ip=ip)
        self.rep(other, status="Failure", ip=ip)
        b = build_case_report(case, self.request, now=NOW).blocks[0]
        self.assertEqual(b.band, "Inconclusive")
        self.assertEqual({(ln.icon, ln.label) for ln in b.connectors}, {("⚪", "failed")})
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

    def test_zero_confidence_means_not_scored(self):
        row = {"type": "ip", "value": "203.0.113.7", "derived_from": None, "sources": [],
               "verdict": {"band": "Inconclusive", "confidence": 0, "rationale": []}}
        self.assertIsNone(build_block(row, now=NOW).confidence)

    def test_vt_link_outside_virustotal_is_dropped(self):
        row = {"type": "ip", "value": "203.0.113.7", "verdict": None, "derived_from": None, "sources": [{
            "name": "VirusTotal_GetReport_3_1", "tier": 1, "verdict": "malicious", "failed": False,
            "enrichment": {"source": "virustotal", "vt_link": "javascript:alert(1)", "link": "javascript:alert(1)"},
            "report": VT_IP}]}
        b = build_block(row, now=NOW)
        self.assertEqual(b.vt_link, "https://www.virustotal.com/gui/ip-address/203.0.113.7")


    def test_vt_source_with_stats_wins_over_a_newer_one_without(self):
        def src(name, report):
            return {"name": name, "tier": 1, "verdict": "malicious", "failed": False,
                    "enrichment": {"source": "virustotal"}, "report": report}
        row = {"type": "domain", "value": "login-example.test", "verdict": None, "derived_from": None,
               "sources": [src("VirusTotal_Scan_3_1", {"results": {"data": {"id": "x"}}}),
                           src("VirusTotal_GetReport_3_1", VT_DOMAIN)]}
        b = build_block(row, now=NOW)
        vt_rows = dict(next(g.rows for g in b.details if g.title == "VirusTotal"))
        self.assertEqual(vt_rows["Detections"], "2/91")
        labels = {c.name: c.label for c in b.connectors}
        self.assertEqual(labels["VirusTotal_GetReport_3_1"], "2/91 detections")
        self.assertNotIn("detections", labels["VirusTotal_Scan_3_1"])


class MailFileTests(Base):
    def mail_case(self, **mail_kw):
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test", date=NOW, to="a@x.test", mail_id="m1", **mail_kw)
        case = Case.objects.create(description="d", reporter=self.user)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        return mail, case

    def embed(self, mail, t, attr, cls, f, o):
        ma = MailArtifact.objects.create(mail=mail, artifact_type=t)
        setattr(ma, attr, cls.objects.create(artifact=ma, **{f: o}))
        ma.save(update_fields=[attr])

    def attach(self, mail, name):
        f = File.objects.create(linked_hash=Hash.objects.create(value=name * 8), file_path=name, tmp_path="", other_names="")
        MailAttachment.objects.create(mail=mail, file=f)
        return f

    def test_mail_case_blocks_only_flagged_non_address_indicators(self):
        header = MailHeader.objects.create(header_value="h", fuzzy_hash="f")
        body = MailBody.objects.create(body_value="b", fuzzy_hash="f")
        mail, case = self.mail_case(mail_header=header, mail_body=body)
        url, ip, addr = URL.objects.create(address="https://evil.test/x"), IP.objects.create(address="203.0.113.9"), MailAddress.objects.create(address="bad@evil.test")
        self.embed(mail, "URL", "artifactIsUrl", ArtifactIsUrl, "url", url)
        self.embed(mail, "IP", "artifactIsIp", ArtifactIsIp, "ip", ip)
        self.embed(mail, "MailAddress", "artifactIsMailAddress", ArtifactIsMailAddress, "mail_address", addr)
        self.rep(self.vt, "malicious", url=url)
        self.rep(self.vt, "safe", ip=ip)
        self.rep(self.vt, "malicious", mail=addr)
        hdr = Analyzer.objects.create(name="Mail_Header_Analyzer", analyzer_cortex_id="mh", tier=2)
        ai_name = ai_analyzer_name()  # configured name differs per deployment
        aim = Analyzer.objects.create(name=ai_name, analyzer_cortex_id="ai", tier=2)
        self.rep(hdr, "safe", mail_header=header)
        self.rep(aim, "malicious", mail_body=body)  # a target the collector reaches
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual(rep.kind, "mail")
        self.assertEqual([b.value for b in rep.blocks], ["https://evil.test/x"])
        self.assertEqual({r.type for r in rep.rows}, {"url", "ip", "mail"})
        self.assertIn("Mail_Header_Analyzer", [ln.name for ln in rep.case_connectors])
        self.assertNotIn(ai_name, [ln.name for ln in rep.case_connectors])

    def test_mail_rows_sort_by_band_then_value(self):
        mail, case = self.mail_case()
        ips = {v: IP.objects.create(address=v) for v in ("198.51.100.1", "zz.test", "aa.test")}
        for o in ips.values():
            self.embed(mail, "IP", "artifactIsIp", ArtifactIsIp, "ip", o)
        self.rep(self.vt, "safe", ip=ips["198.51.100.1"])
        self.rep(self.vt, "malicious", ip=ips["zz.test"])
        self.rep(self.vt, "suspicious", ip=ips["aa.test"])
        rep = build_case_report(case, self.request, now=NOW)
        self.assertEqual([(r.value, r.band) for r in rep.rows],
                         [("zz.test", "Dangerous"), ("aa.test", "Suspicious"), ("198.51.100.1", "Safe")])
        self.assertEqual([b.value for b in rep.blocks], ["zz.test", "aa.test"])

    def test_case_connectors_keep_every_attachment_verdict(self):
        mail, case = self.mail_case(mail_header=MailHeader.objects.create(header_value="h", fuzzy_hash="f"))
        a, b = self.attach(mail, "a.exe"), self.attach(mail, "b.txt")
        fi = Analyzer.objects.create(name="FileInfo", analyzer_cortex_id="fi", tier=2)
        solo = Analyzer.objects.create(name="Mail_Header_Analyzer", analyzer_cortex_id="mh", tier=2)
        self.rep(fi, "malicious", file=a)
        self.rep(fi, "safe", file=b)  # newer
        self.rep(solo, "safe", mail_header=mail.mail_header)
        lines = build_case_report(case, self.request, now=NOW).case_connectors
        by_name = {ln.name: ln.icon for ln in lines}
        self.assertEqual(by_name, {"FileInfo (a.exe)": "\U0001F534", "FileInfo (b.txt)": "\U0001F7E2",
                                   "Mail_Header_Analyzer": "\U0001F7E2"})

    def test_attachment_label_is_the_basename_not_the_stored_path(self):
        mail, case = self.mail_case(mail_header=MailHeader.objects.create(header_value="h", fuzzy_hash="f"))
        a, b = self.attach(mail, "files/sub/invoice.pdf"), self.attach(mail, "b.txt")
        av = Analyzer.objects.create(name="ClamAV", analyzer_cortex_id="cl", tier=2)
        self.rep(av, "malicious", file=a)
        self.rep(av, "safe", file=b)
        names = [ln.name for ln in build_case_report(case, self.request, now=NOW).case_connectors]
        self.assertIn("ClamAV (invoice.pdf)", names)
        self.assertNotIn("ClamAV (files/sub/invoice.pdf)", names)

    def test_file_case_analysis_hides_zero_confidence(self):
        h = Hash.objects.create(value="d" * 64)
        f = File.objects.create(linked_hash=h, file_path="x.bin", tmp_path="", other_names="")
        case = Case.objects.create(description="d", reporter=self.user, results="Inconclusive", final_confidence=0)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, file=f)
        case.save()
        self.assertIsNone(build_case_report(case, self.request, now=NOW).case_analysis.confidence)

    def test_file_case_analysis_leaves_out_the_legacy_ai_report(self):
        h = Hash.objects.create(value="c" * 64)
        f = File.objects.create(linked_hash=h, file_path="x.bin", tmp_path="", other_names="")
        ai_name = ai_analyzer_name()
        self.rep(Analyzer.objects.create(name=ai_name, analyzer_cortex_id="ai", tier=2), "malicious", file=f)
        self.rep(self.vt, "malicious", full=VT_HASH, hash=h)
        case = Case.objects.create(description="d", reporter=self.user, results="Dangerous")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, file=f)
        case.save()
        names = [c.name for c in build_case_report(case, self.request, now=NOW).case_analysis.connectors]
        self.assertNotIn(ai_name, names)
        self.assertIn("VirusTotal_GetReport_3_1", names)

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


class AiSectionTests(Base):
    """Review focus 4: the AI section is mail-only, connector-gated and redacted for the reporter."""

    mail_case = MailFileTests.mail_case

    def setUp(self):
        super().setUp()
        self.analyst = get_user_model().objects.create_user("cert", "", "x")
        self.analyst.groups.add(Group.objects.get_or_create(name="CERT")[0])
        ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": True})
        _, self.mail_case_obj = self.mail_case()
        self.assess(self.mail_case_obj)

    def assess(self, case, **kw):
        defaults = dict(model_version="v3", result="UNWANTED", sub_class="spam", score=6, confidence=80,
                        tier="high", probabilities={"UNWANTED": 0.8, "SAFE": 0.2})
        return AiAssessment.objects.create(case=case, **{**defaults, **kw})

    def build(self, user, case=None):
        request = APIRequestFactory().get("/")
        request.user = user
        # a fresh instance, as the views load it: no stale ai_assessment cache
        return build_case_report(Case.objects.get(pk=(case or self.mail_case_obj).pk), request, now=NOW)

    def in_campaign(self, case):
        sibling_mail, sibling = self.mail_case()
        camp = Campaign.objects.create(title="c")
        CampaignMember.objects.create(campaign=camp, case=case)
        CampaignMember.objects.create(campaign=camp, case=sibling)
        LabelRecord.objects.create(
            message_id="<m@x.test>", message_id_hash="h", case=sibling, source="imap_folder", label="Dangerous",
            label_class="Dangerous", trust="folder", status="active")

    def test_analyst_gets_section_and_cross_check(self):
        rep = self.build(self.analyst)
        self.assertEqual((rep.ai["result"], rep.ai["sub_class"], rep.ai["tier"]), ("Unwanted", "spam", "high"))
        self.assertIsNotNone(rep.ai["cross_check"])
        self.assertRegex(rep.ai["analysed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIn(("\U0001F7E0", "AI model", "Unwanted, High confidence"),
                      [(ln.icon, ln.name, ln.label) for ln in rep.case_connectors])

    def test_analyst_sees_campaign_labels_reporter_does_not(self):
        self.in_campaign(self.mail_case_obj)
        self.assertEqual(self.build(self.analyst).ai["campaign"]["labels"], {"Dangerous": 1})
        rep = self.build(self.user, self.mail_case_obj)  # self.user reported the case
        self.assertIsNotNone(rep.ai["campaign"])
        self.assertNotIn("labels", rep.ai["campaign"])
        self.assertNotIn("members_disagree", rep.ai["campaign"])

    def test_reporter_sees_no_cross_check(self):
        rep = self.build(self.user)
        self.assertEqual(rep.ai["result"], "Unwanted")
        self.assertIsNone(rep.ai["cross_check"])

    def test_no_section_without_assessment(self):
        AiAssessment.objects.all().delete()
        rep = self.build(self.analyst)
        self.assertIsNone(rep.ai)
        self.assertNotIn("AI model", [ln.name for ln in rep.case_connectors])

    def test_no_section_when_connector_disabled(self):
        ConnectorState.objects.filter(name="ai_model").update(enabled=False)
        rep = self.build(self.analyst)
        self.assertIsNone(rep.ai)
        self.assertNotIn("AI model", [ln.name for ln in rep.case_connectors])

    def test_low_tier_shows_runner_up_and_bare_label_without_tier(self):
        AiAssessment.objects.all().delete()
        self.assess(self.mail_case_obj, tier="low")
        rep = self.build(self.analyst)
        self.assertEqual(rep.ai["runner_up"], {"result": "Safe"})
        self.assertIn("Unwanted, Low confidence", [ln.label for ln in rep.case_connectors])
        AiAssessment.objects.all().delete()
        self.assess(self.mail_case_obj, tier="")
        self.assertIn("Unwanted", [ln.label for ln in self.build(self.analyst).case_connectors])

    def test_ai_line_sorts_first_within_its_icon(self):
        hdr = Analyzer.objects.create(name="Aaa_Header", analyzer_cortex_id="aa", tier=1)
        self.rep(hdr, "suspicious", mail_header=self.mail_case_obj.fileOrMail.mail.mail_header
                 or self._header())
        names = [ln.name for ln in self.build(self.analyst).case_connectors if ln.icon == "\U0001F7E0"]
        self.assertEqual(names[0], "AI model")

    def _header(self):
        mail = self.mail_case_obj.fileOrMail.mail
        mail.mail_header = MailHeader.objects.create(header_value="h", fuzzy_hash="f")
        mail.save()
        return mail.mail_header

    def test_group_and_file_cases_never_get_the_section(self):
        _, group = self.group_case()
        self.assess(group)
        self.assertIsNone(self.build(self.analyst, group).ai)
        f = File.objects.create(linked_hash=Hash.objects.create(value="c" * 64), file_path="x.bin", tmp_path="", other_names="")
        fcase = Case.objects.create(description="d", reporter=self.user)
        fcase.fileOrMail = CaseHasFileOrMail.objects.create(case=fcase, file=f)
        fcase.save()
        self.assess(fcase)
        self.assertIsNone(self.build(self.analyst, fcase).ai)
