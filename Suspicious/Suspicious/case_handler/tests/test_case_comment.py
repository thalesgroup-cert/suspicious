from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case, CaseComment


class CaseCommentModelTest(TestCase):
    def setUp(self):
        self.reporter = get_user_model().objects.create_user(username="cc_reporter", password="x")
        self.analyst = get_user_model().objects.create_user(username="cc_analyst", password="x")
        self.case = Case.objects.create(description="", reporter=self.reporter)

    def test_default_is_internal_false(self):
        comment = CaseComment.objects.create(case=self.case, author=self.reporter, body="hello")
        self.assertFalse(comment.is_internal)

    def test_newest_first_ordering(self):
        first = CaseComment.objects.create(case=self.case, author=self.reporter, body="first")
        second = CaseComment.objects.create(case=self.case, author=self.analyst, body="second", is_internal=True)
        ordered_ids = list(CaseComment.objects.filter(case=self.case).values_list("id", flat=True))
        self.assertEqual(ordered_ids, [second.id, first.id])

    def test_deleting_case_cascades_comments(self):
        CaseComment.objects.create(case=self.case, author=self.reporter, body="hello")
        self.case.delete()
        self.assertEqual(CaseComment.objects.count(), 0)

    def test_reverse_accessor_from_case(self):
        CaseComment.objects.create(case=self.case, author=self.reporter, body="hello")
        self.assertEqual(self.case.comments.count(), 1)
