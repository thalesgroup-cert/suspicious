from django.conf import settings
from django.test import SimpleTestCase

EXPECTED_APP_LOGGERS = [
    "api", "case_handler", "cortex_job", "score_process", "connectors",
    "mail_feeder", "email_process", "url_process", "ip_process",
    "hash_process", "file_process", "domain_process", "dashboard",
    "settings", "profiles", "tasp", "suspicious",
]


class TestAppLoggerCoverage(SimpleTestCase):
    def test_every_target_app_has_a_configured_logger(self):
        configured = settings.LOGGING["loggers"]
        missing = [name for name in EXPECTED_APP_LOGGERS if name not in configured]
        self.assertEqual(missing, [], f"missing logger config for: {missing}")

    def test_every_target_app_has_a_dedicated_handler(self):
        handlers = settings.LOGGING["handlers"]
        missing = [
            name for name in EXPECTED_APP_LOGGERS
            if f"{name}_file" not in handlers
        ]
        self.assertEqual(missing, [], f"missing handler config for: {missing}")

    def test_app_loggers_do_not_propagate(self):
        for name in EXPECTED_APP_LOGGERS:
            with self.subTest(logger=name):
                self.assertFalse(settings.LOGGING["loggers"][name]["propagate"])

    def test_app_logger_names_have_no_duplicates(self):
        self.assertEqual(len(EXPECTED_APP_LOGGERS), len(set(EXPECTED_APP_LOGGERS)))
