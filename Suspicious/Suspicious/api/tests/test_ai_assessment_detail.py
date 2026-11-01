from django.contrib.auth.models import Group, User
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from connectors.models import ConnectorState


@override_settings(ROOT_URLCONF="suspicious.urls")
class AiAssessmentDetailTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u", password="pw-12345")
        self.user.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.case = Case.objects.create(description="d", reporter=self.user)
        self.urls = {
            "submission": f"/api/submissions/{self.case.pk}/",
            "investigation": f"/api/investigations/{self.case.pk}/",
        }

    def _enable(self, enabled=True):
        ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": enabled})

    def _assess(self, case=None):
        return AiAssessment.objects.create(
            case=case or self.case, model_version="v0", result="DANGEROUS", score=9, confidence=90
        )

    def _get(self, kind):
        response = self.client.get(self.urls[kind])
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_enabled_with_assessment_gives_payload(self):
        self._enable()
        self._assess()
        for kind in self.urls:
            with self.subTest(kind):
                self.assertEqual(self._get(kind)["ai_assessment"]["result"], "Dangerous")

    def test_disabled_gives_none_even_with_assessment(self):
        self._enable(False)
        self._assess()
        for kind in self.urls:
            with self.subTest(kind):
                self.assertIsNone(self._get(kind)["ai_assessment"])

    def test_enabled_without_assessment_gives_none(self):
        self._enable()
        for kind in self.urls:
            with self.subTest(kind):
                self.assertIsNone(self._get(kind)["ai_assessment"])

    def test_assessment_and_campaign_add_no_query(self):
        self._enable()
        other = Case.objects.create(description="o", reporter=self.user)
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        CampaignMember.objects.create(campaign=campaign, case=other)
        for kind, url in self.urls.items():
            with self.subTest(kind):
                self._get(kind)  # warm caches (content types, permissions)
                with CaptureQueriesContext(connection) as without:
                    self._get(kind)
                self._assess()
                with CaptureQueriesContext(connection) as with_:
                    body = self._get(kind)
                self.assertEqual(body["ai_assessment"]["campaign"]["size"], 2)
                self.assertEqual(len(with_), len(without))
                AiAssessment.objects.all().delete()
