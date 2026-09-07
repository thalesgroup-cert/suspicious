from unittest.mock import patch

from django.test import TestCase, override_settings
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroupArtifact


# The stub URLConf used by suspicious.test_settings (suspicious/test_urls.py)
# omits the submit routes, so pin the real URLConf for this suite.
@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmitIndicatorsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_bulk_creates_one_case_with_group(self, _mock):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8\n1.1.1.1\nhttp://a.test"}, format="json")
        self.assertEqual(r.status_code, 201)
        case = Case.objects.get(id=r.json()["case_id"])
        self.assertIsNotNone(case.observable_group_id)
        self.assertEqual(ObservableGroupArtifact.objects.filter(group=case.observable_group).count(), 3)
        self.assertEqual(r.json()["observable_count"], 3)

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_junk_lines_are_skipped_not_fatal(self, _mock):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8\n!!!garbage!!!"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["skipped"], ["!!!garbage!!!"])

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_safelinks_wrapped_url_also_creates_the_real_target(self, _mock):
        wrapped = ("https://x.safelinks.protection.outlook.com/?url="
                   "https%3A%2F%2Fevil.test%2Fphish&reserved=0")
        r = self.client.post("/api/submit/indicators/", {"indicators": wrapped}, format="json")
        self.assertEqual(r.status_code, 201)
        case = Case.objects.get(id=r.json()["case_id"])
        addrs = set(
            ObservableGroupArtifact.objects
            .filter(group=case.observable_group, artifact_type="URL")
            .values_list("url__address", flat=True)
        )
        self.assertIn("https://evil.test/phish", addrs)   # real target extracted
        self.assertEqual(len(addrs), 2)                    # wrapper kept too

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_unwrapped_target_still_ssrf_checked(self, _mock):
        wrapped = ("https://x.safelinks.protection.outlook.com/?url="
                   "http%3A%2F%2F169.254.169.254%2Flatest&reserved=0")
        r = self.client.post("/api/submit/indicators/", {"indicators": wrapped}, format="json")
        self.assertEqual(r.status_code, 201)
        case = Case.objects.get(id=r.json()["case_id"])
        addrs = list(
            ObservableGroupArtifact.objects
            .filter(group=case.observable_group, artifact_type="URL")
            .values_list("url__address", flat=True)
        )
        self.assertNotIn("http://169.254.169.254/latest", addrs)

    def test_zero_valid_is_400(self):
        r = self.client.post("/api/submit/indicators/", {"indicators": "??? ###"}, format="json")
        self.assertEqual(r.status_code, 400)

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_ssrf_url_indicator_is_skipped_not_dispatched(self, _mock):
        r = self.client.post(
            "/api/submit/indicators/",
            {"indicators": "8.8.8.8\nhxxp://169[.]254[.]169[.]254/latest/meta-data/"},
            format="json",
        )
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertEqual(body["observable_count"], 1)  # only 8.8.8.8
        self.assertEqual(len(body["skipped"]), 1)
        case = Case.objects.get(id=body["case_id"])
        self.assertFalse(
            ObservableGroupArtifact.objects.filter(
                group=case.observable_group, artifact_type="URL"
            ).exists()
        )

    def test_oversized_blob_is_rejected(self):
        blob = "8.8.8.8\n" * 40000  # ~320 KB, over the 100*2048 field cap
        r = self.client.post("/api/submit/indicators/", {"indicators": blob}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_over_cap_is_400(self):
        blob = "\n".join(f"10.0.0.{i}" for i in range(1, 130))
        r = self.client.post("/api/submit/indicators/", {"indicators": blob}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("100", r.json().get("detail", ""))

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        r = self.client.post("/api/submit/indicators/", {"indicators": "8.8.8.8"}, format="json")
        self.assertIn(r.status_code, (401, 403))

    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_dispatch_is_enqueued_with_all_observables(self, mock_delay):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8\n1.1.1.1\nhttp://a.test"}, format="json")
        self.assertEqual(r.status_code, 201)
        mock_delay.assert_called_once()
        _case_id, intents = mock_delay.call_args[0]
        self.assertEqual(len(intents), 3)

    @patch("api.views.submit.dispatch_case_analysis.delay")
    @patch("case_handler.case_utils.case_creator.CaseCreator.create_case", return_value=None)
    def test_case_creation_failure_is_500_not_traceback(self, _mock_create, _mock_delay):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8"}, format="json")
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json()["code"], "internal_error")
