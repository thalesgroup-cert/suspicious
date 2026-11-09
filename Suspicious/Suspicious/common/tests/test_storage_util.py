from django.test import SimpleTestCase

from common.storage.util import content_disposition


class ContentDispositionTests(SimpleTestCase):
    def test_matches_the_s3_form(self):
        self.assertEqual(content_disposition("a b é.eml"),
                         "attachment; filename*=UTF-8''a%20b%20%C3%A9.eml")
