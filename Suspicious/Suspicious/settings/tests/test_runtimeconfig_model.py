from django.test import TestCase

from settings.models import RuntimeConfig


class RuntimeConfigModelTest(TestCase):
    def test_jsonfield_preserves_types(self):
        RuntimeConfig.objects.create(key="x.int", value=42)
        RuntimeConfig.objects.create(key="x.bool", value=True)
        RuntimeConfig.objects.create(key="x.list", value=["a", "b"])
        assert RuntimeConfig.objects.get(key="x.int").value == 42
        assert RuntimeConfig.objects.get(key="x.bool").value is True
        assert RuntimeConfig.objects.get(key="x.list").value == ["a", "b"]

    def test_key_is_unique(self):
        RuntimeConfig.objects.create(key="dup", value=1)
        with self.assertRaises(Exception):
            RuntimeConfig.objects.create(key="dup", value=2)

    def test_scope_defaults_to_backend(self):
        rc = RuntimeConfig.objects.create(key="x.y", value=1)
        assert rc.scope == "backend"

    def test_same_key_allowed_in_two_scopes(self):
        RuntimeConfig.objects.create(scope="shared", key="storage.s3", value={"a": 1})
        RuntimeConfig.objects.create(scope="feeder", key="storage.s3", value={"a": 2})
        assert RuntimeConfig.objects.filter(key="storage.s3").count() == 2

    def test_scope_key_unique_together(self):
        RuntimeConfig.objects.create(scope="shared", key="dup", value=1)
        with self.assertRaises(Exception):
            RuntimeConfig.objects.create(scope="shared", key="dup", value=2)
