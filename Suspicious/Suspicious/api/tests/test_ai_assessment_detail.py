from django.contrib.auth.models import Group, User
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from api.serializers.investigations import InvestigationDetailsSerializer
from api.serializers.submissions import SubmissionDetailsSerializer
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
        # Baseline is the same request with the connector off: it still reads the
        # connector state but never touches the assessment or campaign relations.
        other = Case.objects.create(description="o", reporter=self.user)
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        CampaignMember.objects.create(campaign=campaign, case=other)
        self._assess()
        for kind in self.urls:
            with self.subTest(kind):
                self._enable(False)
                self._get(kind)  # warm caches (content types, permissions)
                with CaptureQueriesContext(connection) as off:
                    self._get(kind)
                self._enable()
                with CaptureQueriesContext(connection) as on:
                    body = self._get(kind)
                self.assertEqual(body["ai_assessment"]["campaign"]["size"], 2)
                self.assertEqual(len(on), len(off))

    def test_no_request_in_context_gives_none(self):
        self._enable()
        self._assess()
        for cls in (SubmissionDetailsSerializer, InvestigationDetailsSerializer):
            with self.subTest(cls.__name__):
                self.assertIsNone(cls().get_ai_assessment(self.case))

    def test_similar_case_the_viewer_cannot_open_is_dropped(self):
        self._enable()
        viewer = User.objects.create_user(username="plain", password="pw-12345")
        stranger = User.objects.create_user(username="stranger", password="pw-12345")
        mine = Case.objects.create(description="m", reporter=viewer)
        hidden = Case.objects.create(description="h", reporter=stranger)
        entry = {"similarity": 0.9, "label": "Dangerous", "provenance": "analyst"}
        AiAssessment.objects.create(
            case=mine, model_version="v0", result="SAFE", score=1, confidence=90,
            similar_cases=[{**entry, "case_id": hidden.pk}, {**entry, "case_id": mine.pk}],
        )
        self.client.force_authenticate(viewer)
        body = self.client.get(f"/api/submissions/{mine.pk}/").json()
        self.assertEqual([e["case_id"] for e in body["ai_assessment"]["similar_cases"]], [mine.pk])

    def test_non_elevated_owner_gets_the_plain_serializer_with_the_key(self):
        self._enable()
        owner = User.objects.create_user(username="owner", password="pw-12345")
        mine = Case.objects.create(description="m", reporter=owner)
        self._assess(mine)
        self.client.force_authenticate(owner)
        response = self.client.get(f"/api/submissions/{mine.pk}/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["ai_assessment"]["result"], "Dangerous")
        self.assertNotIn("raw", body)

    def test_admin_serializer_returns_the_key(self):
        self._enable()
        self.user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self._assess()
        body = self._get("submission")
        self.assertIn("raw", body)
        self.assertEqual(body["ai_assessment"]["result"], "Dangerous")
