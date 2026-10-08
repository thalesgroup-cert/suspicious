from unittest import mock

from django.test import SimpleTestCase

from suspicious.warmup import warm_up


class WarmUpTests(SimpleTestCase):
    def test_loads_the_urlconf_and_reports_the_time(self):
        elapsed = warm_up()
        self.assertIsInstance(elapsed, float)
        self.assertGreaterEqual(elapsed, 0.0)

    def test_is_safe_to_repeat(self):
        warm_up()
        self.assertIsInstance(warm_up(), float)

    def test_a_failure_is_swallowed(self):
        with mock.patch("django.urls.get_resolver", side_effect=ImportError("boom")):
            self.assertIsNone(warm_up())
