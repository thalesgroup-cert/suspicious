"""The UI base URL TheHive alerts link from, derived from email.links.submissions.

A trailing slash on the configured link used to leave "/submissions" in the base, so
alert links read "https://host/submissions/investigation?open=1" (a page that does not exist).
"""
from unittest.mock import patch

from django.test import SimpleTestCase

from connectors.contrib.thehive.connector import _email_settings


class UiBaseTests(SimpleTestCase):
    def base(self, link):
        with patch("settings.config.get_section", return_value={"links": {"submissions": link}}):
            return _email_settings()[0]

    def test_link_forms_all_give_the_site_root(self):
        for link in (
            "https://sus.example/submissions",
            "https://sus.example/submissions/",
            "https://sus.example/submissions//",
            "https://sus.example/",
            "https://sus.example",
        ):
            self.assertEqual(self.base(link), "https://sus.example", link)

    def test_a_path_prefix_is_kept(self):
        self.assertEqual(self.base("https://corp.example/suspicious/submissions/"), "https://corp.example/suspicious")

    def test_unset_link_gives_empty_base(self):
        self.assertEqual(self.base(""), "")
        self.assertEqual(self.base(None), "")
