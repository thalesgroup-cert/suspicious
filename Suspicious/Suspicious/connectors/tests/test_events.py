from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from connectors.events import build_case_event


class BuildCaseEventTest(TestCase):
    def test_snapshot_fields(self):
        user = get_user_model().objects.create_user(
            username="rep", email="rep@example.com", password="x"
        )
        case = Case.objects.create(
            reporter=user, status="Done", results="Dangerous",
            final_score=9.0, confidence=75.0,
            description="test case",
        )
        event = build_case_event("case_finalised", case)
        self.assertEqual(event.schema_version, 1)
        self.assertEqual(event.event, "case_finalised")
        self.assertEqual(event.case_id, case.id)
        self.assertEqual(event.status, "Done")
        self.assertEqual(event.results, "Dangerous")
        self.assertEqual(event.final_score, 9.0)
        self.assertEqual(event.reporter_email, "rep@example.com")
        self.assertTrue(event.created_at)  # ISO timestamp
