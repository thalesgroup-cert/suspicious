"""GET /api/campaigns/summary/: period KPIs and campaigns (identical sourceRefs)."""
from datetime import datetime, timezone
from unittest import mock

from django.contrib.auth.models import Group, User
from django.core.cache import cache
from rest_framework.test import APITestCase

from api.services.campaigns.summary import ACTIVE_WINDOW_HOURS, get_campaign_summary
from api.tests.test_campaigns_service import FakeCollection

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
URL = "/api/campaigns/summary/"


def msg(i, when, classification="SAFE", refs=None, case=None, subject=None):
    meta = {"sent_date": when, "classification": classification}
    if refs is not None:
        meta["sourceRefs"] = refs
    if case is not None:
        meta["suspicious_case_id"] = case
    if subject is not None:
        meta["subject"] = subject
    return (f"m{i}", None, meta)


class SummaryServiceTests(APITestCase):
    def setUp(self):
        cache.clear()
        patcher = mock.patch("api.services.campaigns.summary._now", return_value=NOW)
        patcher.start()
        self.addCleanup(patcher.stop)

    def summary(self, rows, days=7):
        with mock.patch(
            "api.services.campaigns.summary.get_chroma_collection",
            return_value=FakeCollection(rows) if rows is not None else None,
        ):
            return get_campaign_summary(days)

    def test_totals_previous_split_share_peak_and_mix(self):
        rows = [
            msg(1, "2026-10-07T00:00:00Z", "DANGEROUS"),       # first day of period
            msg(2, "2026-10-06T23:59:59Z", "DANGEROUS"),       # last day of previous
            msg(3, "2026-09-30T00:00:00Z", "SAFE"),            # first day of previous
            msg(4, "2026-09-29T23:59:59Z", "SAFE"),            # before both: ignored
            msg(5, "2026-10-09T10:00:00Z", "SUSPICIOUS"),
            msg(6, "2026-10-09T11:00:00Z", "UNWANTED"),
            msg(7, "2026-10-07T05:00:00Z", "SAFE"),
            msg(8, "2026-10-13T11:00:00Z", "NONE"),
            msg(9, "2026-10-07T01:00:00+02:00", "SAFE"),       # 10-06 23:00 UTC: previous
            msg(10, "2026-10-14T00:00:00Z", "DANGEROUS"),      # future-dated: skipped
            ("nodate", None, {"classification": "DANGEROUS"}),
        ]
        s = self.summary(rows)
        self.assertEqual(s["days"], 7)
        self.assertEqual(str(s["period"]["start"]), "2026-10-07")
        self.assertEqual(str(s["period"]["end"]), "2026-10-13")
        self.assertEqual(s["messages"], 5)
        self.assertEqual(s["previous_messages"], 3)
        self.assertEqual(s["unclassified"], 1)
        self.assertEqual(s["dangerous"], 1)
        self.assertEqual(s["previous_dangerous"], 1)
        self.assertAlmostEqual(s["dangerous_share"], 0.2)
        self.assertAlmostEqual(s["previous_dangerous_share"], 1 / 3)
        # 10-07 and 10-09 both have 2: earliest wins
        self.assertEqual(str(s["peak_day"]["date"]), "2026-10-07")
        self.assertEqual(s["peak_day"]["count"], 2)
        self.assertEqual(s["mix"], {"SAFE": 1, "UNWANTED": 1, "SUSPICIOUS": 1, "DANGEROUS": 1})
        self.assertEqual(s["active_window_hours"], ACTIVE_WINDOW_HOURS)

    def test_campaign_grouping_active_and_largest(self):
        rows = [
            msg(1, "2026-10-08T09:00:00Z", "DANGEROUS", ["b.example", "a.example"], "11", "Invoice"),
            msg(2, "2026-10-08T08:00:00Z", "SAFE", '["a.example", "b.example"]', "10"),
            msg(3, "2026-10-12T13:00:00Z", "SAFE", ["a.example", "b.example"], "12", "Later"),
            msg(4, "2026-10-08T10:00:00Z", "SAFE", ["c.example"], "20", "Old one"),
            msg(5, "2026-10-09T10:00:00Z", "SAFE", None, "30"),      # no refs: not a campaign
            msg(6, "2026-10-09T10:00:00Z", "SAFE", [], "31"),
            msg(7, "2026-10-01T10:00:00Z", "SAFE", ["a.example", "b.example"], "1"),  # previous
        ]
        s = self.summary(rows)
        self.assertEqual(len(s["campaigns"]), 2)
        ab, c = s["campaigns"]
        self.assertEqual(ab["name"], "a.example, b.example")
        self.assertEqual(ab["messages"], 3)
        self.assertEqual(ab["dangerous"], 1)
        self.assertAlmostEqual(ab["dangerous_share"], 1 / 3)
        self.assertEqual(ab["case_ids"], ["12", "11", "10"])  # most recent first
        self.assertEqual(ab["sample_subject"], "Invoice")
        self.assertEqual(ab["first_seen"], datetime(2026, 10, 8, 8, tzinfo=timezone.utc))
        self.assertEqual(ab["last_seen"], datetime(2026, 10, 12, 13, tzinfo=timezone.utc))
        self.assertTrue(ab["active"])  # 23 h before NOW
        self.assertFalse(c["active"])  # 5 days before NOW
        self.assertEqual(s["active_campaigns"], 1)
        self.assertEqual(s["largest_campaign"], {"name": "a.example, b.example", "messages": 3})

    def test_case_ids_keep_most_recent_20(self):
        rows = [
            msg(i, f"2026-10-{8 + i // 24:02d}T{i % 24:02d}:00:00Z", refs=["x"], case=str(100 + i))
            for i in range(30)
        ]
        s = self.summary(rows)
        self.assertEqual(s["campaigns"][0]["messages"], 30)
        self.assertEqual(s["campaigns"][0]["case_ids"], [str(100 + i) for i in range(29, 9, -1)])

    def test_active_boundary_is_inclusive(self):
        rows = [
            msg(1, "2026-10-11T12:00:00Z", refs=["edge"]),     # exactly 48 h before NOW
            msg(2, "2026-10-11T11:59:59Z", refs=["stale"]),
        ]
        s = self.summary(rows)
        active = {c["name"]: c["active"] for c in s["campaigns"]}
        self.assertEqual(active, {"edge": True, "stale": False})

    def test_scan_failure_returns_empty_and_is_not_cached(self):
        def exploding(_collection):
            yield {"sent_date": "2026-10-10T10:00:00Z", "classification": "DANGEROUS",
                   "sourceRefs": ["x"]}
            raise RuntimeError("chroma went away")

        with mock.patch(
            "api.services.campaigns.summary.get_chroma_collection",
            return_value=FakeCollection([]),
        ), mock.patch("api.services.campaigns.summary.iter_metadata_dicts", exploding):
            s = get_campaign_summary(7)
        self.assertEqual((s["messages"], s["dangerous"], s["unclassified"]), (0, 0, 0))
        self.assertEqual(s["campaigns"], [])
        self.assertIsNone(s["dangerous_share"])
        self.assertIsNone(cache.get("campaigns:summary:7"))

    def test_empty_store(self):
        s = self.summary(None)
        self.assertEqual(s["messages"], 0)
        self.assertEqual(s["previous_messages"], 0)
        self.assertIsNone(s["dangerous_share"])
        self.assertIsNone(s["previous_dangerous_share"])
        self.assertEqual(s["unclassified"], 0)
        self.assertIsNone(s["peak_day"])
        self.assertEqual(s["campaigns"], [])
        self.assertEqual(s["active_campaigns"], 0)
        self.assertIsNone(s["largest_campaign"])
        self.assertEqual(s["mix"], {"SAFE": 0, "UNWANTED": 0, "SUSPICIOUS": 0, "DANGEROUS": 0})


class SummaryEndpointTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.cert = User.objects.create_user("cert-sum@meridian.example", password="x")
        self.cert.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.plain = User.objects.create_user("plain-sum@meridian.example", password="x")

    def test_elevated_user_gets_summary(self):
        self.client.force_authenticate(self.cert)
        with mock.patch("api.services.campaigns.summary.get_chroma_collection", return_value=None):
            resp = self.client.get(URL, {"days": 30})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["days"], 30)
        self.assertEqual(resp.data["campaigns"], [])
        self.assertIsNone(resp.data["peak_day"])

    def test_cached_per_days(self):
        self.client.force_authenticate(self.cert)
        with mock.patch(
            "api.services.campaigns.summary.get_chroma_collection",
            return_value=FakeCollection([]),
        ) as getter:
            self.client.get(URL)
            self.client.get(URL)
            self.client.get(URL, {"days": 7})
        self.assertEqual(getter.call_count, 2)

    def test_default_days_is_15(self):
        self.client.force_authenticate(self.cert)
        with mock.patch("api.services.campaigns.summary.get_chroma_collection", return_value=None):
            resp = self.client.get(URL)
        self.assertEqual(resp.data["days"], 15)
        self.assertIsNone(resp.data["dangerous_share"])

    def test_days_validation(self):
        self.client.force_authenticate(self.cert)
        for bad in (6, 91):
            self.assertEqual(self.client.get(URL, {"days": bad}).status_code, 400)

    def test_non_elevated_user_forbidden(self):
        self.client.force_authenticate(self.plain)
        self.assertEqual(self.client.get(URL).status_code, 403)

    def test_anonymous_rejected(self):
        self.assertIn(self.client.get(URL).status_code, (401, 403))
