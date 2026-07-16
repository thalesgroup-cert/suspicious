import logging

from django.conf import settings
from django.test import SimpleTestCase


class TestRootLoggerSafetyNet(SimpleTestCase):
    def test_root_logger_configured_with_unclassified_handler(self):
        self.assertIn("root", settings.LOGGING)
        self.assertIn("unclassified_file", settings.LOGGING["root"]["handlers"])

    def test_unconfigured_logger_name_propagates_to_root(self):
        bogus = logging.getLogger("totally.bogus.unconfigured.module")
        with self.assertLogs(level="WARNING") as cm:
            bogus.warning("should reach root")
        self.assertTrue(any("should reach root" in line for line in cm.output))
