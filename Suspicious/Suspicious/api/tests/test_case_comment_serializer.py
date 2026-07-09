from django.contrib.auth import get_user_model
from django.test import TestCase

from api.serializers.comments import CaseCommentSerializer
from case_handler.models import Case, CaseComment


class CaseCommentSerializerTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="ccs_user", password="x", email="ccs_user@example.com"
        )
        self.case = Case.objects.create(description="", reporter=self.user)

    def test_serializes_author_email(self):
        comment = CaseComment.objects.create(case=self.case, author=self.user, body="hi")
        data = CaseCommentSerializer(comment).data
        self.assertEqual(data["author_email"], "ccs_user@example.com")
        self.assertEqual(data["body"], "hi")
        self.assertFalse(data["is_internal"])

    def test_rejects_blank_body(self):
        serializer = CaseCommentSerializer(data={"body": "   "})
        self.assertFalse(serializer.is_valid())
        self.assertIn("body", serializer.errors)

    def test_is_internal_not_settable_from_input(self):
        serializer = CaseCommentSerializer(data={"body": "hi", "is_internal": True})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        comment = serializer.save(case=self.case, author=self.user, is_internal=False)
        self.assertFalse(comment.is_internal)
