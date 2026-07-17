"""Regression tests for the audit cleanup batch (M5, L1, L2)."""
import inspect
import unittest

import classes.services.minio_service as ms
from classes.services.mailbox_service import Mailbox


class CleanupTests(unittest.TestCase):
    def test_m5_bucket_name_normalised_to_63(self):
        long = "a" * 100
        self.assertEqual(len(ms._normalize_bucket_name(long)), 63)
        # Short names pass through untouched.
        self.assertEqual(ms._normalize_bucket_name("short-bucket"), "short-bucket")

    def test_l1_exit_has_context_manager_signature(self):
        params = list(inspect.signature(Mailbox.__exit__).parameters)
        self.assertEqual(params, ["self", "exc_type", "exc_val", "exc_tb"])

    def test_l2_no_class_level_mutable_list(self):
        # The shared mutable class attribute was removed.
        self.assertNotIn("fetched_unseen_email_ids", vars(Mailbox))


if __name__ == "__main__":
    unittest.main()
