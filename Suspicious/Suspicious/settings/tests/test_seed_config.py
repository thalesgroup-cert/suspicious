import json
import os
import tempfile
import pathlib

from django.core.management import call_command
from django.test import TestCase

from settings.models import RuntimeConfig


class SeedConfigTest(TestCase):
    def _write(self, tmp_path):
        data = {
            "integrations": {"cortex": {"url": "http://cx", "api_key": "SECRET",
                                         "analyzers": {"ai": "AI"}}},
            "email": {"smtp": {"server": "mail", "port": 587, "password": "PW", "tls": True}},
        }
        p = tmp_path / "settings.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_seeds_nonsecret_sections_and_skips_secrets(self):
        from suspicious import _config_common as cc
        os.environ["SUSPICIOUS_CONFIG_PATH"] = self._write(pathlib.Path(tempfile.mkdtemp()))
        cc.load_settings.cache_clear()

        call_command("seed_config")

        cortex = RuntimeConfig.objects.get(key="integrations.cortex").value
        self.assertEqual(cortex["url"], "http://cx")
        self.assertEqual(cortex["analyzers"], {"ai": "AI"})
        self.assertNotIn("api_key", cortex)

        smtp = RuntimeConfig.objects.get(key="email.smtp").value
        self.assertEqual(smtp["port"], 587)
        self.assertNotIn("password", smtp)

    def test_idempotent(self):
        from suspicious import _config_common as cc
        os.environ["SUSPICIOUS_CONFIG_PATH"] = self._write(pathlib.Path(tempfile.mkdtemp()))
        cc.load_settings.cache_clear()
        call_command("seed_config")
        n1 = RuntimeConfig.objects.count()
        call_command("seed_config")
        self.assertEqual(RuntimeConfig.objects.count(), n1)

    def test_strips_nested_misp_api_keys(self):
        import json as _json
        from suspicious import _config_common as cc
        data = {"integrations": {"misp": {
            "default_tags": {"tlp": "amber"},
            "instances": {"primary": {"url": "http://m", "api_key": "K1"}}}}}
        p = pathlib.Path(tempfile.mkdtemp()) / "settings.json"
        p.write_text(_json.dumps(data))
        os.environ["SUSPICIOUS_CONFIG_PATH"] = str(p)
        cc.load_settings.cache_clear()
        call_command("seed_config")
        misp = RuntimeConfig.objects.get(key="integrations.misp").value
        self.assertEqual(misp["default_tags"], {"tlp": "amber"})
        self.assertNotIn("api_key", misp["instances"]["primary"])
        self.assertEqual(misp["instances"]["primary"]["url"], "http://m")

    def test_sections_seeded_into_their_scope(self):
        import os, tempfile, pathlib, json as _json
        from suspicious import _config_common as cc
        data = {
            "storage": {"s3": {"endpoint": "e", "secret_key": "SK"}},
            "integrations": {"cortex": {"url": "u", "api_key": "AK"}},
            "branding": {"company_name": "Acme"},
        }
        p = pathlib.Path(tempfile.mkdtemp()) / "settings.json"
        p.write_text(_json.dumps(data))
        os.environ["SUSPICIOUS_CONFIG_PATH"] = str(p)
        cc.load_settings.cache_clear()
        call_command("seed_config")
        self.assertEqual(RuntimeConfig.objects.get(key="storage.s3").scope, "shared")
        self.assertEqual(RuntimeConfig.objects.get(key="branding").scope, "shared")
        self.assertEqual(RuntimeConfig.objects.get(key="integrations.cortex").scope, "backend")
        self.assertNotIn("secret_key", RuntimeConfig.objects.get(key="storage.s3").value)
