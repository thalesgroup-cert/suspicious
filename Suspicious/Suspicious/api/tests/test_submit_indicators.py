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

    def test_zero_valid_is_400(self):
        r = self.client.post("/api/submit/indicators/", {"indicators": "??? ###"}, format="json")
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
