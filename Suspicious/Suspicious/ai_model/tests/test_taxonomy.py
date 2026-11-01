from django.test import SimpleTestCase

from ai_model.taxonomy import FOLDERS, canonical, class_of


class TaxonomyTest(SimpleTestCase):
    def test_class_of(self):
        self.assertEqual(class_of("2_WHALING_PHISHING"), "Dangerous")
        self.assertEqual(class_of("1_NEWSLETTER"), "Unwanted")
        self.assertEqual(class_of("0_LEGIT_EXTERNAL_COMMUNICATION"), "Safe")
        self.assertIsNone(class_of("Inbox"))

    def test_folders(self):
        self.assertEqual(len(FOLDERS), 8)
        self.assertTrue(all(class_of(f) for f in FOLDERS))

    def test_the_last_hierarchy_segment_names_the_folder(self):
        for name in ("INBOX.2_CLASSIC_PHISHING", "Review/0_LEGIT_EXTERNAL_COMMUNICATION", "a/b.1_SPAM"):
            with self.subTest(name):
                self.assertIn(canonical(name), FOLDERS)
        self.assertEqual(class_of("INBOX.2_CLASSIC_PHISHING"), "Dangerous")
        self.assertEqual(canonical("Review/0_LEGIT_EXTERNAL_COMMUNICATION"), "0_LEGIT_EXTERNAL_COMMUNICATION")
        for name in ("2_CLASSIC_PHISHING.old", "INBOX", "", "INBOX.9_ODD"):
            with self.subTest(name):
                self.assertIsNone(canonical(name))
                self.assertIsNone(class_of(name))
