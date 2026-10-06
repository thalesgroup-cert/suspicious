from django.contrib.auth.models import Group, User
from rest_framework.test import APITestCase

from cortex_job.models import Analyzer


class AnalyzerTierApiTests(APITestCase):
    def setUp(self):
        user = User.objects.create_user("u", password="p")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)
        self.a = Analyzer.objects.create(name="VT", analyzer_cortex_id="vt1", tier=3)

    def test_get_includes_tier(self):
        r = self.client.get("/api/settings/analyzers/")
        self.assertEqual(r.status_code, 200)
        row = next(x for x in r.json()["results"] if x["id"] == self.a.id)
        self.assertEqual(row["tier"], 3)

    def test_patch_sets_tier(self):
        r = self.client.patch(
            f"/api/settings/analyzers/{self.a.id}/", {"tier": 1}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.a.refresh_from_db()
        self.assertEqual(self.a.tier, 1)

    def test_patch_rejects_invalid_tier(self):
        r = self.client.patch(
            f"/api/settings/analyzers/{self.a.id}/", {"tier": 9}, format="json"
        )
        self.assertEqual(r.status_code, 400)

    def test_patch_rejects_empty_body(self):
        r = self.client.patch(
            f"/api/settings/analyzers/{self.a.id}/", {}, format="json"
        )
        self.assertEqual(r.status_code, 400)
