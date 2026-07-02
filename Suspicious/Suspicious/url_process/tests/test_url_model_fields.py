from django.test import TestCase
from url_process.models import URL


class URLAnalysisFieldsTest(TestCase):
    def test_new_fields_default(self):
        u = URL.objects.create(address="https://x.com/p")
        self.assertEqual(u.canonical_key, "")
        self.assertEqual(u.analysis_status, URL.AnalysisStatus.PENDING)
        self.assertEqual(u.interestingness, 0)
        self.assertIsNone(u.analyzed_url)

    def test_reused_points_at_representative(self):
        rep = URL.objects.create(address="https://x.com/p?id=1")
        dup = URL.objects.create(
            address="https://x.com/p?id=2",
            analysis_status=URL.AnalysisStatus.REUSED,
            analyzed_url=rep,
        )
        self.assertEqual(dup.analyzed_url_id, rep.id)
        self.assertIn(dup, rep.reused_by.all())
