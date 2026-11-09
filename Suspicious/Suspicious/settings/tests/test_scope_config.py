from unittest import mock
from django.core.cache import cache
from django.test import TestCase

from settings import config as cfg
from settings.models import RuntimeConfig


class GetScopeConfigTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_shared_only_for_feeder_scope(self):
        RuntimeConfig.objects.create(scope="shared", key="storage.s3",
                                     value={"endpoint": "e"})
        RuntimeConfig.objects.create(scope="backend", key="integrations.cortex",
                                     value={"url": "u"})
        with mock.patch.object(cfg, "get_secret", return_value="SECRET"):
            result = cfg.get_scope_config("feeder")
        self.assertEqual(result["storage"]["s3"]["endpoint"], "e")
        self.assertEqual(result["storage"]["s3"]["secret_key"], "SECRET")
        self.assertNotIn("integrations", result)

    def test_backend_scope_includes_shared_plus_backend(self):
        RuntimeConfig.objects.create(scope="shared", key="branding",
                                     value={"company_name": "Acme"})
        RuntimeConfig.objects.create(scope="backend", key="integrations.cortex",
                                     value={"url": "u"})
        with mock.patch.object(cfg, "get_secret", return_value="SECRET"):
            result = cfg.get_scope_config("backend")
        self.assertEqual(result["branding"]["company_name"], "Acme")
        self.assertEqual(result["integrations"]["cortex"]["url"], "u")

    def test_unknown_scope_returns_shared_only(self):
        RuntimeConfig.objects.create(scope="shared", key="branding", value={"x": 1})
        with mock.patch.object(cfg, "get_secret", return_value="S"):
            result = cfg.get_scope_config("nope")
        self.assertEqual(result["branding"]["x"], 1)

    def test_email_subsections_coexist_under_one_email_dict(self):
        RuntimeConfig.objects.create(scope="shared", key="email.smtp",
                                     value={"host": "h"})
        RuntimeConfig.objects.create(scope="shared", key="email.content",
                                     value={"subject": "s"})
        RuntimeConfig.objects.create(scope="shared", key="email.links",
                                     value={"portal": "p"})
        RuntimeConfig.objects.create(scope="shared", key="email.socials",
                                     value={"x": "@acme"})
        RuntimeConfig.objects.create(scope="shared", key="email.logos",
                                     value={"header": "logo.png"})
        with mock.patch.object(cfg, "get_secret", return_value="S"):
            result = cfg.get_scope_config("feeder")
        email = result["email"]
        self.assertEqual(email["smtp"]["host"], "h")
        self.assertEqual(email["smtp"]["password"], "S")
        self.assertEqual(email["content"]["subject"], "s")
        self.assertEqual(email["links"]["portal"], "p")
        self.assertEqual(email["socials"]["x"], "@acme")
        self.assertEqual(email["logos"]["header"], "logo.png")


class GcsScopeTests(TestCase):
    def test_gcs_section_is_backend_only_and_its_key_is_secret(self):
        from settings.config import SCOPE_SECTIONS, SECRET_FIELDS

        self.assertIn("storage.gcs", SCOPE_SECTIONS["backend"])
        self.assertNotIn("storage.gcs", SCOPE_SECTIONS["shared"])
        self.assertNotIn("storage.gcs", SCOPE_SECTIONS["feeder"])
        self.assertIn("service_account_json", SECRET_FIELDS["storage.gcs"])
