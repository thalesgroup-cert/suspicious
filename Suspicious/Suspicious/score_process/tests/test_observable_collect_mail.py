from datetime import datetime, timezone as tz

from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl, ArtifactIsIp
from score_process.scoring.observable_collect import mail_observable_reports
from url_process.models import URL
from ip_process.models import IP


class MailObservableReportsTests(TestCase):
    def setUp(self):
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1")
        self.a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="GTI", tier=1)
        self.url = URL.objects.create(address="https://evil.test/x")
        self.ip = IP.objects.create(address="1.2.3.4")
        self._embed("URL", "artifactIsUrl", ArtifactIsUrl, "url", self.url)
        self._embed("IP", "artifactIsIp", ArtifactIsIp, "ip", self.ip)

    def _embed(self, art_type, fk_attr, join_cls, join_field, obj):
        # Mirrors derived_observables._attach_to_case: the MailArtifact carries
        # the FK to the join row, the join row carries the FK back.
        ma = MailArtifact.objects.create(mail=self.mail, artifact_type=art_type)
        join = join_cls.objects.create(artifact=ma, **{join_field: obj})
        setattr(ma, fk_attr, join)
        ma.save(update_fields=[fk_attr])

    def _rep(self, cid, field, obj):
        return AnalyzerReport.objects.create(
            cortex_job_id=cid, type=field, status="Success", analyzer=self.a,
            level="malicious", confidence=90, score=9,
            report_summary={}, report_taxonomy={}, report_full={},
            **{field: obj})

    def test_yields_one_row_per_embedded_observable_with_its_reports(self):
        r = self._rep("j1", "url", self.url)
        rows = {f: (obj, reps) for (_a, obj, f, reps) in mail_observable_reports(self.mail)}
        self.assertEqual(rows["url"][0].pk, self.url.pk)
        self.assertEqual([x.id for x in rows["url"][1]], [r.id])
        self.assertEqual(rows["ip"][0].pk, self.ip.pk)
        self.assertEqual(rows["ip"][1], [])

    def test_single_query_for_reports(self):
        self._rep("j1", "url", self.url)
        # mail_artifacts walk (one select_related query) + one _bucket_reports query.
        with self.assertNumQueries(2):
            list(mail_observable_reports(self.mail))
