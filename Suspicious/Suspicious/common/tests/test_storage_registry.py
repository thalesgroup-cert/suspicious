import os
import subprocess
import sys
from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
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

    def _check(self, env, json_value):
        if env is None:
            os.environ.pop("STORAGE_PROVIDER", None)
        else:
            os.environ["STORAGE_PROVIDER"] = env
        with patch("common.storage.checks.settings_get", return_value=json_value):
            return check_storage_provider(None)

    def test_startup_check_both_unset_passes(self):
        self.assertEqual(self._check(None, None), [])

    def test_startup_check_both_valid_passes(self):
        self.assertEqual(self._check("s3", "s3"), [])

    def test_startup_check_reports_unknown_env_even_if_json_valid(self):
        errors = self._check("nope", "s3")
        self.assertEqual([e.id for e in errors], ["storage.E001"])
        self.assertIn("env", errors[0].msg)

    def test_startup_check_reports_unknown_json_even_if_env_valid(self):
        errors = self._check("s3", "bogus")
        self.assertEqual([e.id for e in errors], ["storage.E001"])
        self.assertIn("settings.json", errors[0].msg)


class ReadyValidationTests(SimpleTestCase):
    def _ready(self, env, json_value):
        if env is None:
            os.environ.pop("STORAGE_PROVIDER", None)
        else:
            os.environ["STORAGE_PROVIDER"] = env
        with patch("common.storage.checks.settings_get", return_value=json_value), \
                patch("suspicious.otel.configure"):
            apps.get_app_config("suspicious").ready()

    def setUp(self):
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)

    def test_unset_and_valid_values_do_not_raise(self):
        self._ready(None, None)
        self._ready("s3", "s3")

    def test_bad_env_value_raises_naming_value_source_and_providers(self):
        with self.assertRaisesRegex(ImproperlyConfigured, r"'nope'.*env STORAGE_PROVIDER.*s3"):
            self._ready("nope", None)

    def test_bad_settings_json_value_raises(self):
        with self.assertRaisesRegex(ImproperlyConfigured, r"'bogus'.*settings.json storage.provider.*s3"):
            self._ready(None, "bogus")


class GcsRegistryTests(SimpleTestCase):
    def setUp(self):
        reset_store_cache()
        self.addCleanup(reset_store_cache)
        env = patch.dict(os.environ, {"STORAGE_PROVIDER": "gcs"})
        env.start()
        self.addCleanup(env.stop)

    def test_gcs_is_registered_and_lazy(self):
        code = ("import sys, common.storage.registry as r\n"
                "assert 'gcs' in r.known_providers()\n"
                "assert 'google.cloud.storage' not in sys.modules\n"
                "assert 'common.storage.gcs' not in sys.modules\n")
        subprocess.run([sys.executable, "-c", code], check=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

    def test_unknown_provider_message_lists_gcs(self):
        os.environ["STORAGE_PROVIDER"] = "nope"
        with patch("settings.config.get_config", return_value=None), \
                self.assertRaisesRegex(StorageConfigError, "nope.*gcs.*s3"):
            get_store()

    def test_get_store_builds_gcs_from_config(self):
        cfg = {"credentials": "anonymous", "api_endpoint": "http://localhost:4443", "project": "p"}
        with patch("settings.config.get_config", return_value=None), \
                patch("settings.config.get_section", return_value=cfg) as section:
            store = get_store()
        section.assert_called_once_with("storage.gcs")
        self.assertEqual(type(store).__name__, "GcsStore")


class GcsDefaultBucketWarningTests(SimpleTestCase):
    def _check(self, provider, s3=None):
        from common.storage.checks import check_gcs_default_buckets

        def get(key, default=None):
            return {"storage.provider": provider}.get(key, (s3 or {}).get(key.rsplit(".", 1)[-1], default)
                                                      if key.startswith("storage.s3.") else default)

        with patch.dict(os.environ, {"STORAGE_PROVIDER": ""}), patch("common.storage.checks.settings_get", get):
            return check_gcs_default_buckets(None)

    def test_gcs_with_default_names_warns(self):
        warnings = self._check("gcs")
        self.assertEqual([w.id for w in warnings], ["storage.W001"])
        for name in ("suspicious-media", "suspicious-avatars", "mail-previews", "analyzer-screenshots"):
            self.assertIn(name, warnings[0].msg)

    def test_explicit_names_are_not_listed(self):
        msg = self._check("gcs", {"media_bucket": "acme-media", "avatars_bucket": "acme-av"})[0].msg
        self.assertNotIn("suspicious-media", msg)
        self.assertNotIn("suspicious-avatars", msg)

    def test_overridden_preview_and_screenshot_buckets_are_not_listed(self):
        from django.test import override_settings

        with override_settings(MAIL_PREVIEW_BUCKET="acme-prev", SCREENSHOT_BUCKET="acme-shots"):
            msg = self._check("gcs")[0].msg
        self.assertNotIn("mail-previews", msg)
        self.assertNotIn("analyzer-screenshots", msg)

    def test_s3_does_not_warn(self):
        self.assertEqual(self._check("s3"), [])
