from unittest.mock import patch, MagicMock
from django.test import SimpleTestCase
from score_process.scoring.screenshots import urlscan

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _resp(content=PNG, status=200):
    m = MagicMock(status_code=status)
    m.iter_content.return_value = [content]
    m.raise_for_status.side_effect = None if status == 200 else Exception("http %d" % status)
    return m


class UrlscanExtractTest(SimpleTestCase):
    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_task_screenshot_url(self, get):
        get.return_value = _resp()
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertEqual(urlscan.extract(full, "url", "http://x"), PNG)

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_wrapped_in_results(self, get):
        get.return_value = _resp()
        full = {"results": {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}}
        self.assertEqual(urlscan.extract(full, "url", "http://x"), PNG)

    def test_no_url_returns_none(self):
        self.assertIsNone(urlscan.extract({"task": {}}, "url", "http://x"))

    def test_non_urlscan_host_rejected(self):
        full = {"task": {"screenshotURL": "https://evil.example/x.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_http_error_returns_none(self, get):
        get.return_value = _resp(status=404)
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get", side_effect=Exception("timeout"))
    def test_timeout_returns_none(self, get):
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_not_a_png_returns_none(self, get):
        get.return_value = _resp(content=b"<html>")
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))
