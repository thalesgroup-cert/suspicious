import json

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework.test import APIClient


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmitIocFileExtractTests(TestCase):
    URL = "/api/submit/indicators/extract/"

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(User.objects.create_user("u", password="p"))

    def _post(self, name, content, content_type="text/plain"):
        if isinstance(content, str):
            content = content.encode()
        return self.client.post(
            self.URL,
            {"file": SimpleUploadedFile(name, content, content_type=content_type)},
            format="multipart",
        )

    def test_txt_list_extracts_and_classifies(self):
        r = self._post("iocs.txt", "8.8.8.8\nevil.example\nhxxp://bad[.]com/x\nnot an ioc")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        lines = body["indicators"].split("\n")
        self.assertIn("8.8.8.8", lines)
        self.assertIn("evil.example", lines)
        self.assertIn("http://bad.com/x", lines)  # refanged
        self.assertEqual(body["found"], 3)
        self.assertIn("an", body["skipped"])  # "not an ioc" tokens

    def test_csv_columns(self):
        r = self._post("iocs.csv", "1.1.1.1,evil.test\n2.2.2.2;phish.test")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["found"], 4)

    def test_json_array_and_objects(self):
        payload = json.dumps(["9.9.9.9", {"value": "malware.test"}, {"nested": ["3.3.3.3"]}])
        r = self._post("iocs.json", payload, content_type="application/json")
        self.assertEqual(r.status_code, 200)
        lines = set(r.json()["indicators"].split("\n"))
        self.assertEqual(lines, {"9.9.9.9", "malware.test", "3.3.3.3"})

    def test_bad_json_falls_back_to_text(self):
        r = self._post("iocs.json", "{ broken 4.4.4.4 evil.test")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["found"], 2)

    def test_rejects_unsupported_extension(self):
        r = self._post("sample.exe", b"MZ\x90\x00")
        self.assertEqual(r.status_code, 400)

    def test_rejects_oversize(self):
        r = self._post("big.txt", b"8.8.8.8 " * 300_000)  # ~2.4 MB
        self.assertEqual(r.status_code, 400)

    def test_missing_file(self):
        self.assertEqual(self.client.post(self.URL, {}, format="multipart").status_code, 400)

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        self.assertIn(self._post("iocs.txt", "8.8.8.8").status_code, (401, 403))

    def test_non_ioc_file_returns_empty(self):
        r = self._post("notes.txt", "the quick brown fox jumped over")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["found"], 0)
        self.assertEqual(r.json()["indicators"], "")
