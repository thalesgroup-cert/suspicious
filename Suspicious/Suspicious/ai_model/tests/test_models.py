from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from ai_model.models import AiAssessment
from case_handler.models import Case


class AiAssessmentTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="u", password="pass")
        self.case = Case.objects.create(description="", reporter=user)

    def _make(self):
        return AiAssessment.objects.create(
            case=self.case, model_version="v0", result="SAFE", score=1, confidence=90
        )

    def test_one_assessment_per_case(self):
        self._make()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._make()

    def test_defaults(self):
        a = self._make()
        self.assertEqual(
            (a.tier, a.embedding_version, a.probabilities, a.similar_cases),
            ("", "cmp-e1", {}, []),
        )
        self.assertEqual(
            (a.sub_class, a.sub_probabilities, a.contributing_phrases, a.campaign_embedding, a.latency_ms),
            ("", {}, [], "", 0),
        )

    def test_reverse_accessor(self):
        a = self._make()
        self.assertEqual(self.case.ai_assessment, a)

    def test_deleting_the_case_deletes_the_assessment(self):
        self._make()
        self.case.delete()
        self.assertFalse(AiAssessment.objects.exists())
