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
