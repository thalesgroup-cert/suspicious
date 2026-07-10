"""Tests for the settings.json schema validator (M8)."""

import unittest

from suspicious.config_schema import (
    ConfigValidationError,
    SuspiciousConfig,
    validate_config,
)


def _minimal_valid() -> dict:
    return {
        "app": {
            "secret_key": (
                "k" * 64
            ),
        },
        "database": {
            "name": "db_suspicious",
            "user": "suspicious",
            "password": "secret",
        },
    }


class ValidateConfigTests(unittest.TestCase):
    def test_minimal_valid_config_passes(self):
        cfg = validate_config(_minimal_valid())
        self.assertEqual(cfg["app"]["secret_key"], "k" * 64)
        self.assertEqual(cfg["database"]["name"], "db_suspicious")
        self.assertEqual(cfg["redis"]["cache_host"], "redis_cache")
        self.assertEqual(cfg["observability"]["opentelemetry"]["enabled"], False)

    def test_missing_secret_key_rejected(self):
        raw = _minimal_valid()
        del raw["app"]["secret_key"]
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(raw)
        self.assertIn("app.secret_key", str(ctx.exception))

    def test_missing_database_password_rejected(self):
        raw = _minimal_valid()
        del raw["database"]["password"]
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(raw)
        self.assertIn("database.password", str(ctx.exception))

    def test_short_secret_key_rejected(self):
        raw = _minimal_valid()
        raw["app"]["secret_key"] = "short"
        with self.assertRaises(ConfigValidationError):
            validate_config(raw)

    def test_placeholder_secret_key_rejected(self):
        raw = _minimal_valid()
        raw["app"]["secret_key"] = "changeme1234567890"
        with self.assertRaises(ConfigValidationError) as ctx:
            validate_config(raw)
        self.assertIn("placeholder", str(ctx.exception).lower())

    def test_unknown_keys_are_allowed(self):
        raw = _minimal_valid()
        raw["app"]["future_field"] = "tolerated"
        raw["unknown_section"] = {"foo": "bar"}
        cfg = validate_config(raw)
        self.assertEqual(cfg["app"]["future_field"], "tolerated")
        self.assertEqual(cfg["unknown_section"]["foo"], "bar")

    def test_replica_block_optional(self):
        raw = _minimal_valid()
        raw["database"]["replica"] = {"host": "db_replica"}
        cfg = validate_config(raw)
        self.assertEqual(cfg["database"]["replica"]["host"], "db_replica")

    def test_typed_access_via_pydantic_model(self):
        cfg = SuspiciousConfig.model_validate(_minimal_valid())
        self.assertEqual(cfg.database.host, "localhost")
        self.assertFalse(cfg.app.debug)
