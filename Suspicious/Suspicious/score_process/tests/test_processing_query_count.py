from unittest.mock import patch

from django.test import TestCase
from django.db import connection, reset_queries
from django.conf import settings
from django.utils import timezone

from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArtifact, MailAttachment, ArtifactIsIp
from score_process.scoring.processing import process_mail


def _count_selects() -> int:
    return sum(
        1 for q in connection.queries
        if q["sql"].lstrip().upper().startswith("SELECT")
    )


class ProcessMailQueryCountTest(TestCase):
    """P3 regression: process_mail must not fire per-row SELECTs on
    attachment.file or artifact.artifactIs*.<leaf> chains.

    The analyzer-reports lookup
    (CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact) is
    intentionally per-row and is patched out here so it does not skew
    the SELECT count — what we actually want to verify is that the
    forward-FK traversals are batched by prefetch_related.
    """

    def _make_mail(self, n: int):
        mail = Mail.objects.create(subject="t", mail_from="a@b.test", date=timezone.now())
        h = Hash.objects.create(value=f"sha256-{mail.pk}")
        for i in range(n):
            ip = IP.objects.create(address=f"10.0.{mail.pk}.{i}")
            artifact = MailArtifact.objects.create(
                mail=mail, artifact_type="IP",
                artifact_score=0, artifact_confidence=0,
            )
            ais = ArtifactIsIp.objects.create(ip=ip, artifact=artifact)
            artifact.artifactIsIp = ais
            artifact.save(update_fields=["artifactIsIp"])

            f = File.objects.create(
                linked_hash=h,
                file_path=f"files/dummy-{mail.pk}-{i}.bin",
                tmp_path="", other_names="",
            )
            MailAttachment.objects.create(mail=mail, file=f)
        return mail

    def test_process_mail_select_count_is_constant(self):
        small = self._make_mail(2)
        large = self._make_mail(20)

        original_debug = settings.DEBUG
        settings.DEBUG = True
        target = (
            "score_process.scoring.cortex_analyzers.reports."
            "CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact"
        )
        try:
            with patch(target, return_value=[]):
                reset_queries()
                process_mail(small, [], [], [], False, 1)
                small_selects = _count_selects()
                reset_queries()
                process_mail(large, [], [], [], False, 1)
                large_selects = _count_selects()
        finally:
            settings.DEBUG = original_debug

        self.assertEqual(
            small_selects, large_selects,
            f"N+1 detected: 2-row case used {small_selects} SELECTs, "
            f"20-row case used {large_selects}",
        )
