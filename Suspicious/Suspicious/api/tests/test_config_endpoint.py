from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from rest_framework.test import APITestCase
from unittest import mock

from settings import config as cfg
from settings.models import RuntimeConfig

User = get_user_model()


class ConfigEndpointTest(APITestCase):
    def setUp(self):
        RuntimeConfig.objects.create(scope="shared", key="storage.s3",
                                     value={"endpoint": "e"})
        RuntimeConfig.objects.create(scope="backend", key="integrations.cortex",
                                     value={"url": "u"})
        self.feeder = User.objects.create_user("svc-feeder", password="x")
        self.feeder.groups.add(Group.objects.create(name="feeder"))

    def _url(self, scope):
        return reverse("service-config", args=[scope])

    def test_requires_auth(self):
        resp = self.client.get(self._url("feeder"))
        self.assertIn(resp.status_code, (401, 403))

    def test_feeder_token_reads_feeder_scope(self):
        self.client.force_authenticate(self.feeder)
        with mock.patch.object(cfg, "get_secret", return_value="SECRET"):
            resp = self.client.get(self._url("feeder"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["storage"]["s3"]["endpoint"], "e")
        self.assertEqual(resp.json()["storage"]["s3"]["secret_key"], "SECRET")
        self.assertNotIn("integrations", resp.json())
        self.assertNotIn("authentication", resp.json())

    def test_feeder_token_cannot_read_backend_scope(self):
        self.client.force_authenticate(self.feeder)
        resp = self.client.get(self._url("backend"))
        self.assertEqual(resp.status_code, 403)

    def test_superuser_reads_any_scope(self):
        su = User.objects.create_superuser("root", "r@x.io", "x")
        self.client.force_authenticate(su)
        with mock.patch.object(cfg, "get_secret", return_value="S"):
            resp = self.client.get(self._url("backend"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["integrations"]["cortex"]["url"], "u")

    def test_shared_scope_not_requestable(self):
        self.client.force_authenticate(self.feeder)
        resp = self.client.get(self._url("shared"))
        self.assertEqual(resp.status_code, 403)

    def test_authenticated_no_groups_cannot_read_any_scope(self):
        nobody = User.objects.create_user("svc-nobody", password="x")
        self.client.force_authenticate(nobody)
        resp = self.client.get(self._url("feeder"))
        self.assertEqual(resp.status_code, 403)
