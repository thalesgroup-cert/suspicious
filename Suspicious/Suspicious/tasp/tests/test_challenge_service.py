import logging
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from tasp.services.challenge import notify_and_record_challenge


class NotifyAndRecordTest(TestCase):
    @patch("tasp.services.challenge.CaseChallengeService.notify")
    @patch("tasp.services.challenge.CaseChallengeService.update_user_stats")
    def test_runs_stats_and_notify_without_validate(self, m_stats, m_notify):
        user = get_user_model().objects.create_user(username="ncs", password="x")
        # Already-challenged case must NOT raise (no validate() here).
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Safe",
        )
        notify_and_record_challenge(case, logging.getLogger("t"))
        m_stats.assert_called_once()
        m_notify.assert_called_once()


class NotifyHeaderTest(TestCase):
    @patch("tasp.services.challenge.ChallengeToTheHiveService")
    @patch("tasp.services.challenge._load_thehive_config", return_value={"enabled": True})
    def test_header_includes_proposal_and_reason(self, _cfg, m_thehive):
        from tasp.services.challenge import CaseChallengeService
        user = get_user_model().objects.create_user(username="hdr", password="x")
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Dangerous", challenge_reason="looks like phishing",
        )
        CaseChallengeService(case, logging.getLogger("t")).notify()
        # mail_header is the 3rd positional arg to ChallengeToTheHiveService.
        header = m_thehive.call_args[0][2]
        self.assertIn("Dangerous", header)
        self.assertIn("looks like phishing", header)
