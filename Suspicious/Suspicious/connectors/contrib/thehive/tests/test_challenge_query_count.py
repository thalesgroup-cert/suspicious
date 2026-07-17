from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, reset_queries
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArtifact, MailAttachment
from connectors.contrib.thehive.challenge import ChallengeToTheHiveService


class ChallengeMailQueryCountTest(TestCase):
    """P1 regression: _build_case_context and _send_thehive_with_mail must not
    fire per-row queries on attachment.file or artifact.artifactIs* chains.
    Query count is asserted equal across small and large fixtures — that
    equality, not the absolute number, is the N+1 guarantee."""

    def _make_mail(self, n: int):
        mail = Mail.objects.create(subject="t", mail_from="a@b.test", date=timezone.now())
        h = Hash.objects.create(value=f"sha256-{mail.pk}")
        for i in range(n):
            MailArtifact.objects.create(
                mail=mail,
                artifact_type="IP",
                artifact_score=0,
                artifact_confidence=0,
            )
            f = File.objects.create(
                linked_hash=h,
                file_path=f"files/dummy-{mail.pk}-{i}.bin",
                tmp_path="",
                other_names="",
            )
            MailAttachment.objects.create(mail=mail, file=f)
        return mail

    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(username="p1_reporter", password="x")
        self.case = Case.objects.create(
            status="Done", description="", reporter=self.reporter,
            score=0, confidence=0, results="Safe",
        )

    def test_build_case_context_query_count_is_constant(self):
        small = self._make_mail(2)
        large = self._make_mail(20)

        challenge = ChallengeToTheHiveService.__new__(ChallengeToTheHiveService)
        challenge.case = self.case

        original_debug = settings.DEBUG
        settings.DEBUG = True
        try:
            reset_queries()
            challenge._build_case_context(small)
            small_count = len(connection.queries)
            reset_queries()
            challenge._build_case_context(large)
            large_count = len(connection.queries)
        finally:
            settings.DEBUG = original_debug

        self.assertEqual(
            small_count, large_count,
            f"N+1 detected: 2-row case used {small_count} queries, "
            f"20-row case used {large_count}",
        )

    def test_send_thehive_with_mail_query_count_is_constant(self):
        small = self._make_mail(2)
        large = self._make_mail(20)

        service = ChallengeToTheHiveService.__new__(ChallengeToTheHiveService)
        service.case = self.case

        challenger = {
            "firstname": "C",
            "lastname": "H",
            "email": "c@h.test",
            "groups": [],
        }

        with patch(
            "connectors.contrib.thehive.challenge.create_alert_from_challenge",
            return_value={"_id": "~stub-alert"},
        ):
            original_debug = settings.DEBUG
            settings.DEBUG = True
            try:
                reset_queries()
                service._send_thehive_with_mail(
                    "https://stub", "key", self.case, small, challenger
                )
                small_count = len(connection.queries)
                reset_queries()
                service._send_thehive_with_mail(
                    "https://stub", "key", self.case, large, challenger
                )
                large_count = len(connection.queries)
            finally:
                settings.DEBUG = original_debug

        self.assertEqual(
            small_count, large_count,
            f"N+1 detected: 2-row case used {small_count} queries, "
            f"20-row case used {large_count}",
        )
