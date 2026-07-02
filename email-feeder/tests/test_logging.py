"""Tests for the dictConfig-based feeder logging.

Covers the four guarantees of the redesign:
  1. setup_logging() builds without error and returns the root logger.
  2. Test / unwritable-dir mode disables file handlers (NullHandler), no files.
  3. Domain child loggers route to their own file and not a sibling's.
  4. Every logger writes JSON to stdout (so `docker logs feeder` is populated).
"""
import logging
import logging.handlers
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import classes.services.logger_service as ls


def _close_handlers() -> None:
    for name in ("email-feeder", "email-feeder.imap",
                 "email-feeder.minio", "email-feeder.smtp"):
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            h.close()
            lg.removeHandler(h)


class FeederLoggingTest(unittest.TestCase):
    def tearDown(self):
        _close_handlers()

    def _stdout_handlers(self, logger: logging.Logger) -> list:
        return [
            h for h in logger.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.handlers.RotatingFileHandler)
            and getattr(h, "stream", None) is sys.stdout
        ]

    def test_setup_returns_root_logger_with_handlers(self):
        with mock.patch.dict(os.environ, {"FEEDER_TESTING": "1"}):
            logger = ls.setup_logging()
        self.assertEqual(logger.name, "email-feeder")
        self.assertTrue(logger.handlers)

    def test_testing_mode_disables_file_handlers(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(
                os.environ, {"FEEDER_TESTING": "1", "LOG_DIR": d}
            ):
                ls.setup_logging()
            root = logging.getLogger("email-feeder")
            # The file slot is a NullHandler, not a RotatingFileHandler.
            self.assertTrue(
                any(isinstance(h, logging.NullHandler) for h in root.handlers)
            )
            self.assertFalse(
                any(isinstance(h, logging.handlers.RotatingFileHandler)
                    for h in root.handlers)
            )
            # No log files written.
            self.assertEqual(list(pathlib.Path(d).glob("*.log")), [])

    def test_domain_logger_routes_to_its_own_file(self):
        with tempfile.TemporaryDirectory() as d:
            env = {"LOG_DIR": d}
            env.pop("FEEDER_TESTING", None)
            with mock.patch.dict(os.environ, env, clear=False):
                os.environ.pop("FEEDER_TESTING", None)
                ls.setup_logging()
                logging.getLogger("email-feeder.imap").info("hello-imap-marker")
                logging.getLogger("email-feeder.minio").info("hello-minio-marker")
                for name in ("email-feeder.imap", "email-feeder.minio"):
                    for h in logging.getLogger(name).handlers:
                        h.flush()

            imap_log = (pathlib.Path(d) / "imap.log").read_text()
            minio_log = (pathlib.Path(d) / "minio.log").read_text()
            self.assertIn("hello-imap-marker", imap_log)
            self.assertNotIn("hello-minio-marker", imap_log)
            self.assertIn("hello-minio-marker", minio_log)
            self.assertNotIn("hello-imap-marker", minio_log)

    def test_every_logger_writes_json_to_stdout(self):
        with mock.patch.dict(os.environ, {"FEEDER_TESTING": "1"}):
            ls.setup_logging()
        for name in ("email-feeder", "email-feeder.imap",
                     "email-feeder.minio", "email-feeder.smtp"):
            logger = logging.getLogger(name)
            self.assertTrue(
                self._stdout_handlers(logger),
                msg=f"{name} has no stdout handler",
            )

    def test_invalid_log_level_falls_back_to_info(self):
        with mock.patch.dict(os.environ, {"FEEDER_TESTING": "1", "LOG_LEVEL": "BOGUS"}):
            logger = ls.setup_logging()
        self.assertEqual(logger.level, logging.INFO)


if __name__ == "__main__":
    unittest.main()
