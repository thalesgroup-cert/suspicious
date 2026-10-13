"""GET /api/campaigns/neighbours/: near-known-bad and novel messages (kNN heuristics
on the PCA sample), backed by the fake Chroma collection."""
import json
import math
from datetime import datetime, timedelta, timezone
from unittest import mock

import numpy as np

from django.contrib.auth.models import Group, User
from django.core.cache import cache
from rest_framework.test import APITestCase

from api.services.campaigns import neighbours
from api.services.campaigns.neighbours import get_campaign_neighbours
from api.tests.test_campaigns_service import FakeCollection

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
URL = "/api/campaigns/neighbours/"
DIM = 8


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def row(rid, vector, label, days_ago=30, case=None):
    meta = {"classification": label, "sent_date": iso(days_ago), "subject": f"subj {rid}"}
    meta["suspicious_case_id"] = case if case is not None else f"case-{rid}"
    return (rid, [float(v) for v in vector], meta)


def axis(i, scale=1.0):
    v = np.zeros(DIM)
    v[i] = scale
    return v


def planted_rows():
    """Dangerous cluster on e0, Safe cluster on e1, three non-dangerous messages planted
    inside the dangerous cluster (recent), a recent far outlier and an old far outlier
    (both leaning slightly towards the Safe cluster so their weak neighbours are Safe)."""
    rng = np.random.default_rng(0)
    rows = []
    for i in range(15):
        rows.append(row(f"d{i}", axis(0) + rng.normal(0, 0.03, DIM), "DANGEROUS"))
    for i in range(15):
        rows.append(row(f"s{i}", axis(1) + rng.normal(0, 0.03, DIM), "SAFE"))
    for i, label in enumerate(("SAFE", "SUSPICIOUS", "SAFE")):
        rows.append(row(f"p{i}", axis(0) + rng.normal(0, 0.03, DIM), label, days_ago=1))
    rows.append(row("new-out", axis(2) + axis(1, 0.2), "SAFE", days_ago=0))
    rows.append(row("old-out", axis(4) + axis(1, 0.2), "SAFE", days_ago=40))
    return rows


class NeighboursServiceTests(APITestCase):
    def setUp(self):
        cache.clear()
        patcher = mock.patch("api.services.campaigns.neighbours._now", return_value=NOW)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_on(self, rows, limit=1500):
        cache.clear()
        with mock.patch(
            "api.services.campaigns.neighbours.get_chroma_collection",
            return_value=FakeCollection(rows) if rows is not None else None,
        ):
            return get_campaign_neighbours(limit)

    def test_near_known_bad_finds_exactly_the_planted_points(self):
        payload = self.run_on(planted_rows())
        bad = payload["near_known_bad"]
        self.assertEqual({i["suspicious_case_id"] for i in bad}, {"case-p0", "case-p1", "case-p2"})
        scores = [i["score"] for i in bad]
        self.assertEqual(scores, sorted(scores, reverse=True))
        for item in bad:
            self.assertGreaterEqual(item["score"], neighbours.BAD_SHARE_THRESHOLD)
            self.assertTrue(item["nearest_dangerous_case_id"].startswith("case-d"))
            self.assertNotEqual(item["label"], "DANGEROUS")
            self.assertEqual(item["mail_subject"], f"subj {item['suspicious_case_id'][5:]}")
            self.assertEqual(str(item["date"]), "2026-10-12")

    def test_novel_finds_the_recent_outlier_not_the_old_one(self):
        novel = self.run_on(planted_rows())["novel"]
        self.assertEqual([i["suspicious_case_id"] for i in novel], ["case-new-out"])
        self.assertGreater(novel[0]["score"], 0.5)
        self.assertLessEqual(novel[0]["score"], 2.0)

    def test_constants_echoed(self):
        payload = self.run_on(planted_rows())
        self.assertEqual(payload["k"], 10)
        self.assertEqual(payload["bad_share_threshold"], 0.6)
        self.assertEqual(payload["novelty_percentile"], 95)
        self.assertEqual(payload["novel_window_days"], 7)

    def test_sample_smaller_than_k_plus_one_is_empty(self):
        rows = planted_rows()[:neighbours.K]
        payload = self.run_on(rows)
        self.assertEqual(payload["near_known_bad"], [])
        self.assertEqual(payload["novel"], [])

    def test_chunk_size_does_not_change_the_result(self):
        baseline = self.run_on(planted_rows())
        with mock.patch.object(neighbours, "CHUNK_ROWS", 2):
            chunked = self.run_on(planted_rows())
        self.assertEqual(baseline, chunked)
        self.assertTrue(baseline["near_known_bad"])

    def test_identical_and_zero_vectors_no_nan(self):
        rows = [row(f"i{n}", np.ones(DIM), "DANGEROUS" if n % 3 else "SAFE", days_ago=0)
                for n in range(14)]
        rows += [row(f"z{n}", np.zeros(DIM), "SAFE", days_ago=0) for n in range(3)]
        payload = self.run_on(rows)
        for item in payload["near_known_bad"] + payload["novel"]:
            self.assertTrue(math.isfinite(item["score"]), item)
            self.assertFalse(item["suspicious_case_id"].startswith("case-z"))
            self.assertNotEqual(item["nearest_dangerous_case_id"], None)
        # identical vectors: every distance is 0, nothing exceeds the percentile
        self.assertEqual(payload["novel"], [])
        self.assertEqual(
            {i["suspicious_case_id"] for i in payload["near_known_bad"]},
            {f"case-i{n}" for n in range(0, 14, 3)},
        )

    def test_isolated_point_is_novel_not_near_known_bad(self):
        # far from everything, but its weak nearest neighbours are all Dangerous
        rows = planted_rows() + [row("iso", axis(6) + axis(0, 0.15), "SAFE", days_ago=0)]
        payload = self.run_on(rows)
        bad_ids = {i["suspicious_case_id"] for i in payload["near_known_bad"]}
        self.assertEqual(bad_ids, {"case-p0", "case-p1", "case-p2"})
        self.assertIn("case-iso", {i["suspicious_case_id"] for i in payload["novel"]})
        with mock.patch.object(neighbours, "CHUNK_ROWS", 2):
            self.assertEqual(self.run_on(rows), payload)

    def test_equal_nn_distances_exclude_nothing(self):
        # two groups of identical vectors: every NN distance equals the percentile
        rows = [row(f"a{i}", axis(0), "DANGEROUS") for i in range(9)]
        rows += [row(f"f{i}", axis(0), "SAFE") for i in range(3)]
        rows += [row(f"b{i}", axis(1), "SAFE") for i in range(12)]
        bad = self.run_on(rows)["near_known_bad"]
        self.assertEqual({i["suspicious_case_id"] for i in bad}, {f"case-f{i}" for i in range(3)})

    def test_duplicates_are_not_novel(self):
        # float32 dot of a vector with its exact duplicate is not always exactly 1
        # seed 2 with 25 pairs reproduces it: a16/b16 came out "novel" with score 0.0
        rng = np.random.default_rng(2)
        rows = []
        for i in range(25):
            v = rng.normal(size=DIM)
            rows += [row(f"a{i}", v, "SAFE", days_ago=0), row(f"b{i}", v, "SAFE", days_ago=0)]
        rows.append(row("out", rng.normal(size=DIM), "SAFE", days_ago=0))
        novel = self.run_on(rows)["novel"]
        self.assertEqual([i["suspicious_case_id"] for i in novel], ["case-out"])
        self.assertGreater(novel[0]["score"], 0.0)
        with mock.patch.object(neighbours, "CHUNK_ROWS", 2):
            self.assertEqual(self.run_on(rows)["novel"], novel)

    def boundary_rows(self, n_dangerous):
        # P at e0; ten neighbours at strictly decreasing similarity along e1
        rows = [row("P", axis(0), "SAFE")]
        for j in range(10):
            label = "DANGEROUS" if 1 <= j <= n_dangerous else "SAFE"
            rows.append(row(f"n{j}", axis(0) + axis(1, 0.1 * (j + 1)), label))
        # far, sparse fillers so P's nearest-neighbour distance is typical
        rows += [row(f"f{j}", axis(3) + axis(4, 0.3 * j), "SAFE") for j in range(10)]
        return rows

    def test_share_boundary_is_inclusive(self):
        bad = {i["suspicious_case_id"]: i for i in self.run_on(self.boundary_rows(6))["near_known_bad"]}
        self.assertIn("case-P", bad)
        self.assertEqual(bad["case-P"]["score"], 0.6)
        self.assertEqual(bad["case-P"]["nearest_dangerous_case_id"], "case-n1")
        self.assertEqual(bad["case-P"]["nearest_dangerous_similarity"], round(1 / math.sqrt(1.04), 6))
        bad5 = self.run_on(self.boundary_rows(5))["near_known_bad"]
        self.assertNotIn("case-P", {i["suspicious_case_id"] for i in bad5})

    def test_nearest_dangerous_similarity_on_both_lists(self):
        payload = self.run_on(planted_rows())
        for item in payload["near_known_bad"]:
            self.assertGreater(item["nearest_dangerous_similarity"], 0.9)
            self.assertLessEqual(item["nearest_dangerous_similarity"], 1.0)
        for item in payload["novel"]:
            self.assertIsNone(item["nearest_dangerous_similarity"])

    def test_lists_capped_at_twenty(self):
        rng = np.random.default_rng(1)
        rows = [row(f"d{i}", axis(0) + rng.normal(0, 0.05, DIM), "DANGEROUS") for i in range(200)]
        rows += [row(f"p{i}", axis(0) + rng.normal(0, 0.05, DIM), "SAFE", days_ago=1)
                 for i in range(25)]
        bad = self.run_on(rows)["near_known_bad"]
        self.assertEqual(len(bad), neighbours.MAX_ITEMS)
        self.assertEqual(len(bad), 20)

    def test_missing_case_id_gives_null_nearest_dangerous(self):
        rows = [row(f"d{i}", axis(0) + 0.01 * i * axis(1), "DANGEROUS", case="") for i in range(12)]
        rows.append(row("p", axis(0) + 0.055 * axis(1), "SAFE"))  # inside the line, not isolated
        bad = self.run_on(rows)["near_known_bad"]
        self.assertEqual(len(bad), 1)
        self.assertIsNone(bad[0]["nearest_dangerous_case_id"])


class NeighboursEndpointTests(APITestCase):
    def setUp(self):
        cache.clear()
        patcher = mock.patch("api.services.campaigns.neighbours._now", return_value=NOW)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cert = User.objects.create_user("cert-nb@meridian.example", password="x")
        self.cert.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.reporter = User.objects.create_user("rep-nb@meridian.example", password="x")
        self.client.force_authenticate(self.cert)

    def patch_collection(self, collection):
        return mock.patch(
            "api.services.campaigns.neighbours.get_chroma_collection", return_value=collection
        )

    def test_endpoint_serializes_and_caches_per_limit(self):
        with self.patch_collection(FakeCollection(planted_rows())) as getter:
            resp = self.client.get(URL)
            self.client.get(URL)
            self.client.get(URL, {"limit": 100})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(getter.call_count, 2)
        data = json.loads(resp.content)
        self.assertEqual(data["k"], 10)
        item = data["near_known_bad"][0]
        self.assertEqual(
            set(item),
            {"suspicious_case_id", "mail_subject", "label", "date", "score",
             "nearest_dangerous_case_id", "nearest_dangerous_similarity"},
        )
        self.assertEqual(item["date"], "2026-10-12")
        self.assertEqual(data["novel"][0]["suspicious_case_id"], "case-new-out")

    def test_identical_vectors_valid_json(self):
        rows = [row(f"i{n}", np.ones(DIM), "SAFE", days_ago=0) for n in range(12)]
        rows.append(row("z", np.zeros(DIM), "SAFE"))
        with self.patch_collection(FakeCollection(rows)):
            resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 200)
        json.loads(resp.content)

    def test_none_and_empty_collection_empty_not_cached(self):
        for collection in (None, FakeCollection([])):
            cache.clear()
            with self.patch_collection(collection) as getter:
                first = self.client.get(URL)
                self.client.get(URL)
            self.assertEqual(getter.call_count, 2)
            self.assertEqual(first.data["near_known_bad"], [])
            self.assertEqual(first.data["novel"], [])
            self.assertEqual(first.data["k"], 10)

    def test_failure_mid_scan_empty_not_cached(self):
        with self.patch_collection(FakeCollection(planted_rows())), mock.patch(
            "api.services.campaigns.service.fetch_records_for_ids",
            side_effect=RuntimeError("chroma went away"),
        ):
            resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["near_known_bad"], [])
        self.assertEqual(resp.data["novel"], [])
        self.assertIsNone(cache.get("campaigns:neighbours:1500"))

    def test_limit_validation(self):
        with self.patch_collection(None):
            for bad in (0, 5001, "x"):
                self.assertEqual(self.client.get(URL, {"limit": bad}).status_code, 400, bad)
            for good in (1, 5000):
                self.assertEqual(self.client.get(URL, {"limit": good}).status_code, 200, good)

    def test_access(self):
        self.client.force_authenticate(self.reporter)
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.client.force_authenticate(None)
        self.assertIn(self.client.get(URL).status_code, (401, 403))
