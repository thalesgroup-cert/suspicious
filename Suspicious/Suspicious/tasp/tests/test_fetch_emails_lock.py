import time
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from tasp.tasks import _FETCH_EMAILS_LOCK_KEY, fetch_emails


class FetchEmailsLockTest(TestCase):
    def tearDown(self):
        cache.delete(_FETCH_EMAILS_LOCK_KEY)

    def test_skips_when_previous_run_still_in_flight(self):
        cache.add(_FETCH_EMAILS_LOCK_KEY, 1, timeout=1800)
        with patch("tasp.cron.fetch_emails.fetch_and_process_emails") as m:
            fetch_emails.apply().get()
        m.assert_not_called()

    def test_runs_and_releases_lock_when_free(self):
        with patch("tasp.cron.fetch_emails.fetch_and_process_emails") as m:
            fetch_emails.apply().get()
        m.assert_called_once()
        self.assertIsNone(cache.get(_FETCH_EMAILS_LOCK_KEY))

    def test_releases_lock_even_on_failure(self):
        with patch(
            "tasp.cron.fetch_emails.fetch_and_process_emails",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(Exception):
                fetch_emails.apply(throw=True).get()
        self.assertIsNone(cache.get(_FETCH_EMAILS_LOCK_KEY))


class FetchEmailsHeartbeatTest(TestCase):
    def setUp(self):
        cache.delete(_FETCH_EMAILS_LOCK_KEY)
        patcher = patch.multiple("tasp.tasks", _FETCH_EMAILS_LOCK_TTL=1, _FETCH_EMAILS_HEARTBEAT=0.2)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(cache.delete, _FETCH_EMAILS_LOCK_KEY)

    def test_long_run_keeps_the_lock_past_the_ttl(self):
        seen = {}

        def slow_run():
            time.sleep(1.8)  # longer than the 1 s TTL: only the heartbeat keeps the key alive
            seen["held"] = cache.get(_FETCH_EMAILS_LOCK_KEY) is not None

        with patch("tasp.cron.fetch_emails.fetch_and_process_emails", side_effect=slow_run):
            fetch_emails.apply().get()
        self.assertTrue(seen["held"])
        self.assertIsNone(cache.get(_FETCH_EMAILS_LOCK_KEY))

    def test_lock_of_a_killed_worker_expires_and_the_next_run_proceeds(self):
        cache.add(_FETCH_EMAILS_LOCK_KEY, "dead-worker", timeout=1)  # nobody renews it
        time.sleep(1.3)
        with patch("tasp.cron.fetch_emails.fetch_and_process_emails") as m:
            fetch_emails.apply().get()
        m.assert_called_once()

    def test_run_does_not_release_a_lock_someone_else_now_holds(self):
        def takeover():
            cache.set(_FETCH_EMAILS_LOCK_KEY, "other-run", timeout=30)

        with patch("tasp.cron.fetch_emails.fetch_and_process_emails", side_effect=takeover):
            fetch_emails.apply().get()
        self.assertEqual(cache.get(_FETCH_EMAILS_LOCK_KEY), "other-run")
