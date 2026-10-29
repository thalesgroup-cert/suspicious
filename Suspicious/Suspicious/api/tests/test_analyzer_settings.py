from django.contrib.auth.models import Group, User
from rest_framework.test import APITestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from url_process.models import URL


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


class AnalyzerWeightGuardTests(APITestCase):
    """The weighted average divides by the sum of weights, so the active sum must stay above 0."""

    def setUp(self):
        user = User.objects.create_user("u", password="p")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)
        self.a = Analyzer.objects.create(name="A", analyzer_cortex_id="a", weight=0.5)
        self.b = Analyzer.objects.create(name="B", analyzer_cortex_id="b", weight=0.0)

    def _patch(self, analyzer, body):
        return self.client.patch(f"/api/settings/analyzers/{analyzer.id}/", body, format="json")

    def test_zero_on_last_weighted_active_analyzer_is_rejected(self):
        r = self._patch(self.a, {"weight": 0.0})
        self.assertEqual(r.status_code, 400)
        self.assertIn("weight", r.json())
        self.a.refresh_from_db()
        self.assertEqual(self.a.weight, 0.5)

    def test_zero_is_allowed_while_another_active_analyzer_has_weight(self):
        self.b.weight = 0.3
        self.b.save()
        r = self._patch(self.a, {"weight": 0.0})
        self.assertEqual(r.status_code, 200)
        self.a.refresh_from_db()
        self.assertEqual(self.a.weight, 0.0)

    def test_inactive_analyzer_does_not_rescue_the_sum(self):
        self.b.weight = 0.9
        self.b.is_active = False
        self.b.save()
        self.assertEqual(self._patch(self.a, {"weight": 0.0}).status_code, 400)

    def test_only_active_analyzer_cannot_be_zeroed(self):
        self.b.delete()
        self.assertEqual(self._patch(self.a, {"weight": 0.0}).status_code, 400)

    def test_inactive_analyzer_update_never_trips_the_guard(self):
        self.b.is_active = False
        self.b.weight = 0.4
        self.b.save()
        self.assertEqual(self._patch(self.b, {"weight": 0.0}).status_code, 200)

    def test_tier_only_update_skips_the_guard(self):
        self.a.weight = 0.0
        self.a.save()
        self.assertEqual(self._patch(self.a, {"tier": 2}).status_code, 200)

    def test_out_of_range_and_non_numeric_still_400(self):
        self.assertEqual(self._patch(self.a, {"weight": 1.5}).status_code, 400)
        self.assertEqual(self._patch(self.a, {"weight": "x"}).status_code, 400)

    def test_non_admin_is_forbidden(self):
        other = User.objects.create_user("plain", password="p")
        self.client.force_authenticate(other)
        self.assertEqual(self._patch(self.a, {"weight": 0.2}).status_code, 403)


class AnalyzerWeightGuardPerKindTests(APITestCase):
    """Scoring divides per kind of evidence, so zeroing the last weighted analyzer of one kind
    would score that evidence Safe even while other kinds keep a positive total."""

    def setUp(self):
        user = User.objects.create_user("u", password="p")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)
        self.url = URL.objects.create(address="https://kind.example")
        self.ip = IP.objects.create(address="7.7.7.7")
        self.url_a = self._analyzer("url_a", 0.5, url=self.url)
        self.url_b = self._analyzer("url_b", 0.0, url=self.url)
        self.ip_c = self._analyzer("ip_c", 0.5, ip=self.ip)  # keeps the global sum positive

    def _analyzer(self, name, weight, **target):
        analyzer = Analyzer.objects.create(name=name, analyzer_cortex_id=name, weight=weight)
        AnalyzerReport.objects.create(
            cortex_job_id=name, type="url" if "url" in target else "ip", status="Success",
            analyzer=analyzer, level="safe", confidence=100, score=0,
            report_summary={}, report_taxonomy={}, report_full={}, **target,
        )
        return analyzer

    def _patch(self, analyzer, weight):
        return self.client.patch(f"/api/settings/analyzers/{analyzer.id}/", {"weight": weight}, format="json")

    def test_zeroing_the_last_weighted_analyzer_of_a_kind_is_rejected(self):
        r = self._patch(self.url_a, 0.0)
        self.assertEqual(r.status_code, 400)
        self.assertIn("url", r.json()["weight"][0])
        self.url_a.refresh_from_db()
        self.assertEqual(self.url_a.weight, 0.5)

    def test_allowed_while_another_analyzer_of_the_kind_keeps_weight(self):
        self.url_b.weight = 0.3
        self.url_b.save()
        self.assertEqual(self._patch(self.url_a, 0.0).status_code, 200)

    def test_a_kind_that_is_already_unweighted_does_not_block_other_edits(self):
        self.url_a.weight = 0.0
        self.url_a.save()
        self.assertEqual(self._patch(self.url_a, 0.0).status_code, 200)

    def test_analyzer_without_reports_is_only_held_to_the_global_rule(self):
        fresh = Analyzer.objects.create(name="fresh", analyzer_cortex_id="fresh", weight=0.4)
        self.assertEqual(self._patch(fresh, 0.0).status_code, 200)
