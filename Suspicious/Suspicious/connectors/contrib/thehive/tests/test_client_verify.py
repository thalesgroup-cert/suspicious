import unittest
from unittest.mock import patch

from connectors.contrib.thehive.client import TheHiveService
from connectors.contrib.thehive.models import TheHiveConfig


class TheHiveServiceVerifyTest(unittest.TestCase):
    def test_empty_certificate_path_falls_back_to_system_trust_store(self):
        config = TheHiveConfig(url="https://thehive.example", api_key="k", certificate_path=None)
        with patch("connectors.contrib.thehive.client.TheHiveApi") as mock_api:
            TheHiveService(config)
        self.assertEqual(mock_api.call_args.kwargs["verify"], True)
