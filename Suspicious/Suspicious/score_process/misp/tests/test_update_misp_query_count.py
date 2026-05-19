from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, reset_queries
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from ip_process.models import IP
from mail_feeder.models import (
    ArtifactIsIp,
    Mail,
    MailArtifact,
)
from score_process.misp.service import MISPService


def _count_selects() -> int:
    return sum(
        1 for q in connection.queries
        if q["sql"].lstrip().upper().startswith("SELECT")
    )


class UpdateMispQueryCountTest(TestCase):
    """P4 regression: update_misp must not fire per-row SELECTs on
    the artifact.artifactIs<Type>.<leaf> forward-FK chain that
    _build_artifact_object walks. External collaborators (MISP API
    client, event manager, object builders) are mocked so what we
    measure is just the ORM cost of the mail-artifact loop.
    """

    def _make_case(self, n: int):
        User = get_user_model()
        reporter = User.objects.create_user(username=f"p4-{n}", password="x")
        mail = Mail.objects.create(subject="t", mail_from="a@b.test", date=timezone.now())
        for i in range(n):
            ip = IP.objects.create(address=f"10.0.{n}.{i}")
            artifact = MailArtifact.objects.create(
                mail=mail, artifact_type="IP",
                artifact_score=0, artifact_confidence=0,
            )
            ais = ArtifactIsIp.objects.create(ip=ip, artifact=artifact)
            artifact.artifactIsIp = ais
            artifact.save(update_fields=["artifactIsIp"])

        case = Case.objects.create(
            description="", reporter=reporter, results="Safe",
        )
        link = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = link
        case.save(update_fields=["fileOrMail"])
        return case

    def test_update_misp_select_count_is_constant(self):
        small = self._make_case(2)
        large = self._make_case(20)

        original_debug = settings.DEBUG
        settings.DEBUG = True
        try:
            with patch("score_process.misp.service.MISPEventManager") as mem_cls, \
                 patch("score_process.misp.service.MISPClient"), \
                 patch("score_process.misp.service.build_email_object", return_value=None), \
                 patch("score_process.misp.service.finalize_misp_object"), \
                 patch("score_process.misp.service.build_ip_object",
                       return_value=MagicMock()), \
                 patch.object(MISPService, "_maybe_push_monthly"):
                mem_cls.return_value.get_or_create_event.return_value = MagicMock(id=1)

                svc = MISPService.__new__(MISPService)
                svc.client = MagicMock()
                svc.primary = True

                reset_queries()
                svc.update_misp(small)
                small_selects = _count_selects()
                reset_queries()
                svc.update_misp(large)
                large_selects = _count_selects()
        finally:
            settings.DEBUG = original_debug

        self.assertEqual(
            small_selects, large_selects,
            f"N+1 detected: 2-row case used {small_selects} SELECTs, "
            f"20-row case used {large_selects}",
        )
