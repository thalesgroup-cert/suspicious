import os
from unittest.mock import patch

from django.test import SimpleTestCase

from common.storage import (
    StorageConfigError, configured_provider_name, get_presign_store, get_store, reset_store_cache,
)
from common.storage.checks import check_storage_provider

S3 = {"endpoint": "rustfs:9000", "public_endpoint": "localhost:35002", "access_key": "ak",
      "secret_key": "sk", "secure": False}


class RegistryTests(SimpleTestCase):
    def setUp(self):
        reset_store_cache()
        self.addCleanup(reset_store_cache)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("STORAGE_PROVIDER", None)
        self.cfg = patch("settings.config.get_config", return_value=None)
        self.cfg.start()
        self.addCleanup(self.cfg.stop)
        sec = patch("settings.config.get_section", return_value=dict(S3))
        sec.start()
        self.addCleanup(sec.stop)

    def test_default_is_s3(self):
        self.assertEqual(configured_provider_name(), "s3")

    def test_env_overrides_default(self):
        os.environ["STORAGE_PROVIDER"] = "nope"
        self.assertEqual(configured_provider_name(), "nope")

    def test_runtime_setting_overrides_env(self):
        os.environ["STORAGE_PROVIDER"] = "nope"
        with patch("settings.config.get_config", return_value="s3"):
            self.assertEqual(configured_provider_name(), "s3")

    def test_unknown_provider_raises_with_known_names(self):
        os.environ["STORAGE_PROVIDER"] = "nope"
        with self.assertRaisesRegex(StorageConfigError, "nope.*s3"):
            get_store()

    def test_store_is_cached_until_reset(self):
        first = get_store()
        self.assertIs(get_store(), first)
        reset_store_cache()
        self.assertIsNot(get_store(), first)

    def test_db_unavailable_falls_back_to_env(self):
        os.environ["STORAGE_PROVIDER"] = "s3"
        with patch("settings.config.get_config", side_effect=RuntimeError("db down")):
            self.assertEqual(configured_provider_name(), "s3")
            os.environ["STORAGE_PROVIDER"] = "nope"
            self.assertEqual(configured_provider_name(), "nope")

    def test_presign_store_uses_public_endpoint(self):
        self.assertIn("localhost:35002", get_presign_store()._client.meta.endpoint_url)
        self.assertIn("rustfs:9000", get_store()._client.meta.endpoint_url)

    def test_startup_check_reports_unknown_provider(self):
        self.assertEqual(check_storage_provider(None), [])
        os.environ["STORAGE_PROVIDER"] = "nope"
        errors = check_storage_provider(None)
        self.assertEqual([e.id for e in errors], ["storage.E001"])
