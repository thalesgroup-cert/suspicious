import json
import unittest

from mail_feeder import submission_contract as sc


class SubmissionContractTests(unittest.TestCase):
    def test_email_dir_pattern_matches_feeder_dirs(self):
        self.assertTrue(sc.EMAIL_DIR_PATTERN.match("260326141159-abc123"))
        self.assertFalse(sc.EMAIL_DIR_PATTERN.match("analysis_0"))

    def test_build_status_shape(self):
        s = sc.build_status(
            sc.STATUS_TODO,
            submission_id="260326141159-deadbeef",
            reported_by="user@corp.com",
            emails_to_analyze=["260326141159-aa/ref.eml"],
            attachments=["260326141159-aa/attachments/x.pdf"],
            submitted_at="2026-06-24T10:00:00+00:00",
        )
        self.assertEqual(s["status"], "todo")
        self.assertEqual(s["submission_id"], "260326141159-deadbeef")
        self.assertEqual(s["reported_by"], "user@corp.com")
        self.assertEqual(s["schema"], sc.CONTRACT_SCHEMA)

    def test_parse_status_roundtrip(self):
        raw = json.dumps({"status": "processing", "submission_id": "x"}).encode()
        self.assertEqual(sc.parse_status(raw)["status"], "processing")

    def test_parse_status_rejects_missing_status(self):
        with self.assertRaises(ValueError):
            sc.parse_status(b'{"submission_id": "x"}')
