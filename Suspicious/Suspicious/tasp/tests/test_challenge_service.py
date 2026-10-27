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
        header = m_thehive.call_args[0][2]
        self.assertIn("Dangerous", header)
        self.assertIn("looks like phishing", header)


class PushChallengeTaskTest(TestCase):
    def _case(self):
        user = get_user_model().objects.create_user(username="pct", password="x")
        return Case.objects.create(description="", reporter=user, is_challenged=True)

    @patch("tasp.services.challenge.send_challenge_to_thehive")
    def test_notify_queues_the_push_instead_of_running_it_inline(self, m_send):
        from tasp.services.challenge import CaseChallengeService
        case = self._case()
        with patch("tasp.services.challenge._load_thehive_config", return_value={"enabled": True}), \
             patch("tasp.tasks.push_challenge_to_thehive.delay") as m_delay:
            CaseChallengeService(case, logging.getLogger("t")).notify()
        m_delay.assert_called_once()
        self.assertEqual(m_delay.call_args.args[0], case.id)
        m_send.assert_not_called()

    def test_a_failing_push_is_retried_with_backoff(self):
        from celery.exceptions import Retry
        from tasp.tasks import push_challenge_to_thehive
        case = self._case()
        with patch("tasp.services.challenge.send_challenge_to_thehive", side_effect=ConnectionError("down")), \
             patch.object(push_challenge_to_thehive, "retry", side_effect=Retry()) as m_retry:
            with self.assertRaises(Retry):
                push_challenge_to_thehive.run(case.id, "header")
        self.assertEqual(m_retry.call_args.kwargs["countdown"], 60)

    def test_a_deleted_case_is_skipped(self):
        from tasp.tasks import push_challenge_to_thehive
        with patch("tasp.services.challenge.send_challenge_to_thehive") as m_send:
            push_challenge_to_thehive.run(999999, "header")
        m_send.assert_not_called()
