import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.test import SimpleTestCase


class NarrationSpikeCommandTest(SimpleTestCase):
    def _write_fixture(self, tmp_dir, band="Dangerous"):
        fixture = {
            "verdict": {"band": band, "score": 9.0, "confidence": 85, "rule": "malicious-count"},
            "analyzer_reports": [{"analyzer": "VirusTotal_v3", "report_full": {"positives": 50, "total": 70}}],
        }
        path = Path(tmp_dir) / "fixture.json"
        path.write_text(json.dumps(fixture))
        return path

    @patch("score_process.management.commands.narration_spike.requests.post")
    def test_writes_pass_result_when_narration_matches_verdict(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "This case is Dangerous based on strong evidence."},
        )
        mock_post.return_value.raise_for_status = lambda: None

        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture_path = self._write_fixture(tmp_dir)
            call_command("narration_spike", str(fixture_path))

            result_path = fixture_path.with_suffix(fixture_path.suffix + ".result.txt")
            self.assertTrue(result_path.exists())
            content = result_path.read_text()
            self.assertIn("STATUS: PASS", content)
            self.assertIn("This case is Dangerous", content)

    @patch("score_process.management.commands.narration_spike.requests.post")
    def test_writes_fail_result_when_narration_contradicts_verdict(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "This case looks Safe, no action needed."},
        )
        mock_post.return_value.raise_for_status = lambda: None

        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture_path = self._write_fixture(tmp_dir)
            call_command("narration_spike", str(fixture_path))

            result_path = fixture_path.with_suffix(fixture_path.suffix + ".result.txt")
            content = result_path.read_text()
            self.assertIn("STATUS: FAIL", content)
            self.assertIn("contradicting band 'Safe'", content)
