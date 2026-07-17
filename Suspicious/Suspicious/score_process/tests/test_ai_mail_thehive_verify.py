from unittest.mock import patch
from django.test import SimpleTestCase

from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser


class AiMailThehiveVerifyTest(SimpleTestCase):
    def test_certificate_path_passed_through_not_coerced_to_bool(self):
        parser = AiMailParser.__new__(AiMailParser)
        with patch(
            "settings.config.get_section",
            return_value={"url": "https://thehive.example", "api_key": "k",
                          "certificate_path": "/etc/private/rootcafile.pem"},
        ):
            self.assertEqual(parser._thehive["verify"], "/etc/private/rootcafile.pem")
