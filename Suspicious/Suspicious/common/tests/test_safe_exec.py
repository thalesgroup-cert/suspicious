import logging

from django.test import SimpleTestCase

from common.safe_exec import make_safe_execution


class MakeSafeExecutionTest(SimpleTestCase):
    def test_yields_without_error_on_success(self):
        ran = []
        safe_execution = make_safe_execution("unit")
        with safe_execution("do work"):
            ran.append(True)
        self.assertEqual(ran, [True])

    def test_logs_with_prefix_and_reraises_on_error(self):
        logger = logging.getLogger("test.safe_exec")
        safe_execution = make_safe_execution("web_submission", logger)
        with self.assertLogs(logger, level="ERROR") as captured:
            with self.assertRaises(ValueError):
                with safe_execution("creating case"):
                    raise ValueError("boom")
        self.assertEqual(len(captured.records), 1)
        message = captured.records[0].getMessage()
        self.assertIn("[web_submission]", message)
        self.assertIn("creating case", message)
        self.assertIn("boom", message)
        # exc_info attached so the traceback is logged
        self.assertIsNotNone(captured.records[0].exc_info)

    def test_defaults_logger_to_prefix_named_logger(self):
        safe_execution = make_safe_execution("case_creator")
        with self.assertLogs("case_creator", level="ERROR"):
            with self.assertRaises(RuntimeError):
                with safe_execution("creating case"):
                    raise RuntimeError("x")
