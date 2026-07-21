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
