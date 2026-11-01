from django.test import SimpleTestCase

from ai_model.taxonomy import FOLDERS, class_of


class TaxonomyTest(SimpleTestCase):
    def test_class_of(self):
        self.assertEqual(class_of("2_WHALING_PHISHING"), "Dangerous")
        self.assertEqual(class_of("1_NEWSLETTER"), "Unwanted")
        self.assertEqual(class_of("0_LEGIT_EXTERNAL_COMMUNICATION"), "Safe")
        self.assertIsNone(class_of("Inbox"))

    def test_folders(self):
        self.assertEqual(len(FOLDERS), 8)
        self.assertTrue(all(class_of(f) for f in FOLDERS))
