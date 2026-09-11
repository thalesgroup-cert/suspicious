from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case

User = get_user_model()


def _make_user(username, *, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class InvestigationGlobalEditVerdictExplanationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("ge_reporter")
        self.analyst = _make_user("ge_analyst", groups=["CERT"])

    @patch("api.views.investigations.MailNotificationService")
    def test_patch_clears_stale_verdict_explanation(self, _mail):
        case = Case.objects.create(
            reporter=self.reporter, description="", results="Dangerous",
            verdict_explanation={"band": "Dangerous", "reporter_paragraph": "old"},
        )
        self.client.force_authenticate(self.analyst)
        resp = self.client.patch(
            reverse("investigation-edit-global", kwargs={"case_id": case.id}),
            {"score": 1, "confidence": 20, "classification": "SAFE"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        case.refresh_from_db()
        self.assertEqual(case.results, "Safe")
        self.assertIsNone(case.verdict_explanation)
