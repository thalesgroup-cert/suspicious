from unittest import mock

from django.core.cache import cache
from django.test import TestCase

from settings import config as cfg
from settings.models import RuntimeConfig


class GetConfigTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_db_value_wins_over_settings_json(self):
        RuntimeConfig.objects.create(key="integrations.cortex.url", value="http://db")
        self.assertEqual(cfg.get_config("integrations.cortex.url"), "http://db")

    def test_missing_key_falls_back_to_settings_json(self):
        with mock.patch.object(cfg, "settings_get", return_value="http://json") as m:
            self.assertEqual(cfg.get_config("some.unseeded.key"), "http://json")
            m.assert_called()

    def test_missing_everywhere_returns_default(self):
        with mock.patch.object(cfg, "settings_get", return_value=None):
            self.assertEqual(cfg.get_config("nope", default="D"), "D")

    def test_cache_hit_avoids_db(self):
        RuntimeConfig.objects.create(key="k", value="v1")
        self.assertEqual(cfg.get_config("k"), "v1")
        RuntimeConfig.objects.filter(key="k").update(value="v2")
        self.assertEqual(cfg.get_config("k"), "v1")  # still cached

    def test_invalidate_on_save(self):
        rc = RuntimeConfig.objects.create(key="k", value="v1")
        self.assertEqual(cfg.get_config("k"), "v1")
        rc.value = "v2"
        rc.save()  # save() calls invalidate_cache
        self.assertEqual(cfg.get_config("k"), "v2")


class GetSectionTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_merges_db_nonsecret_and_vault_secret(self):
        RuntimeConfig.objects.create(
            key="integrations.cortex",
            value={"url": "http://db", "analyzers": {"ai": "AI"}},
        )
        with mock.patch.object(cfg, "get_secret", return_value="SECRET") as gs:
            section = cfg.get_section("integrations.cortex")
        self.assertEqual(section["url"], "http://db")
        self.assertEqual(section["analyzers"], {"ai": "AI"})
        self.assertEqual(section["api_key"], "SECRET")
        self.assertEqual(section["webhook_secret"], "SECRET")
        self.assertEqual(gs.call_count, 2)

    def test_section_falls_back_to_settings_json_when_no_db_row(self):
        with mock.patch.object(
            cfg, "settings_get",
            return_value={"url": "http://json", "api_key": "ignored"},
        ), mock.patch.object(cfg, "get_secret", return_value="SECRET"):
            section = cfg.get_section("integrations.thehive")
        self.assertEqual(section["url"], "http://json")
        self.assertEqual(section["api_key"], "SECRET")  # secret overlaid from Vault
