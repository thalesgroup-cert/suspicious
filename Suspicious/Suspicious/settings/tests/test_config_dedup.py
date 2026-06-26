"""Regression tests for duplicate RuntimeConfig rows across scopes.

A section that changed scope between releases (e.g. storage.s3 moved from
"backend" to "shared") leaves a stale row under the old scope. get_config must
deterministically prefer the canonical-scope row, and seed_config must purge the
stale duplicates so only one row per key survives.
"""
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase

from settings.config import get_config
from settings.models import RuntimeConfig


class ConfigDedupLookupTests(TestCase):
    def setUp(self):
        cache.clear()
        RuntimeConfig.objects.all().delete()

    def test_get_config_prefers_canonical_scope_over_stale_duplicate(self):
        # Stale row under the OLD scope (inserted first → naive .first() picks it).
        RuntimeConfig.objects.create(
            scope="backend", key="storage.s3",
            value={"endpoint": "x", "media_bucket": "m"},
        )
        # Current row under the canonical scope (shared) carries feeder_bucket.
        RuntimeConfig.objects.create(
            scope="shared", key="storage.s3",
            value={"endpoint": "x", "media_bucket": "m", "feeder_bucket": "suspicious-feeder"},
        )
        cache.clear()
        got = get_config("storage.s3")
        self.assertEqual(got.get("feeder_bucket"), "suspicious-feeder")


class SeedConfigPurgeTests(TestCase):
    def setUp(self):
        cache.clear()
        RuntimeConfig.objects.all().delete()

    def test_seed_purges_stale_scope_duplicates(self):
        # Pre-existing stale duplicate under the wrong scope.
        RuntimeConfig.objects.create(
            scope="backend", key="storage.s3", value={"endpoint": "stale"},
        )
        call_command("seed_config")
        rows = RuntimeConfig.objects.filter(key="storage.s3")
        self.assertEqual(rows.count(), 1, "stale-scope duplicate must be purged")
        self.assertEqual(rows.first().scope, "shared")
