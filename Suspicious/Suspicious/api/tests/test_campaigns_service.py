"""Campaign endpoints backed by a fake Chroma collection: PCA (3 components +
date), four-bucket classification counts, period-aware mail volume."""
import math
from datetime import datetime, timedelta, timezone
from unittest import mock

import numpy as np

from django.contrib.auth.models import Group, User
from django.core.cache import cache
from rest_framework.test import APITestCase

from api.services.campaigns.service import CampaignQueryService, empty_pca_payload


class FakeCollection:
    """Just enough of chromadb's Collection.get for the campaigns helpers."""

    def __init__(self, rows):
        # rows: list of (id, embedding, metadata)
        self.rows = rows

    def get(self, ids=None, include=None, limit=None, offset=0):
        rows = self.rows
        if ids is not None:
            wanted = set(ids)
            rows = [r for r in rows if r[0] in wanted]
        else:
            rows = rows[offset:offset + limit] if limit is not None else rows
        return {
            "ids": [r[0] for r in rows],
            "embeddings": [r[1] for r in rows],
            "metadatas": [r[2] for r in rows],
        }


def patch_collection(collection):
    return mock.patch(
        "api.services.campaigns.service.get_chroma_collection", return_value=collection
    )


class CampaignPcaTests(APITestCase):
    def _pca(self, rows):
        with patch_collection(FakeCollection(rows)):
            return CampaignQueryService().get_pca(1500)

    def assert_finite(self, payload):
        self.assertEqual(len(payload["explained_variance"]), 3)
        for value in payload["explained_variance"]:
            self.assertTrue(math.isfinite(value))
        for p in payload["points"]:
            for axis in ("x", "y", "z"):
                self.assertTrue(math.isfinite(p[axis]), p)

    def test_three_components_and_dates(self):
        rows = [
            (f"id{i}", [float(i), float(i * i % 7), float((i * 3) % 5), float(i % 2)],
             {"classification": "safe", "sent_date": f"2026-10-0{i + 1}T10:00:00Z"})
            for i in range(6)
        ]
        rows.append(("nodate", [9.0, 1.0, 2.0, 0.0], {"classification": "DANGEROUS"}))
        payload = self._pca(rows)
        self.assert_finite(payload)
        self.assertLessEqual(sum(payload["explained_variance"]), 1.0 + 1e-9)
        self.assertGreater(payload["explained_variance"][2], 0.0)
        self.assertTrue(any(p["z"] != 0.0 for p in payload["points"]))
        undated = [p for p in payload["points"] if p["label"] == "DANGEROUS"]
        self.assertEqual(undated[0]["date"], None)
        self.assertIn("2026-10-01", [p["date"] for p in payload["points"]])

    def test_third_component_is_the_third(self):
        # axes with known variances 18 > 8 > 2 (sum of squares), centred at 0
        coords = [(3, 0, 0), (-3, 0, 0), (0, 2, 0), (0, -2, 0), (0, 0, 1), (0, 0, -1)]
        rows = [(f"k{i}", [float(v) for v in c], {}) for i, c in enumerate(coords)]
        payload = self._pca(rows)
        r = payload["explained_variance"]
        self.assertGreaterEqual(r[0], r[1])
        self.assertGreaterEqual(r[1], r[2])
        for axis, expected in (("x", 18 / 28), ("y", 8 / 28), ("z", 2 / 28)):
            share = sum(p[axis] ** 2 for p in payload["points"]) / 28
            self.assertAlmostEqual(share, expected)
        self.assertAlmostEqual(r[2], 2 / 28)

    def test_component_signs_are_deterministic(self):
        rows = [
            (f"s{i}", [float(i), float(i * i % 7), float((i * 3) % 5), float(i % 2)], {})
            for i in range(8)
        ]
        baseline = self._pca(rows)
        real_svd = np.linalg.svd

        def flipped_svd(*args, **kwargs):
            u, s, vt = real_svd(*args, **kwargs)
            return -u, s, -vt

        with mock.patch("api.services.campaigns.service.np.linalg.svd", flipped_svd):
            flipped = self._pca(rows)
        self.assertEqual(baseline, flipped)

    def test_single_vector(self):
        payload = self._pca([("a", [1.0, 2.0, 3.0], {"classification": "safe", "subject": "Hi"})])
        self.assert_finite(payload)
        self.assertEqual(payload["explained_variance"], [0.0, 0.0, 0.0])
        self.assertEqual(payload["points"][0]["z"], 0.0)
        self.assertEqual(payload["points"][0]["date"], None)

    def test_one_dim_vectors(self):
        payload = self._pca([("a", [1.0], {}), ("b", [3.0], {}), ("c", [5.0], {})])
        self.assert_finite(payload)
        self.assertEqual(payload["explained_variance"], [1.0, 0.0, 0.0])
        self.assertTrue(all(p["y"] == 0.0 and p["z"] == 0.0 for p in payload["points"]))

    def test_two_vectors(self):
        payload = self._pca([("a", [1.0, 0.0, 4.0], {}), ("b", [0.0, 2.0, 1.0], {})])
        self.assert_finite(payload)
        self.assertTrue(all(p["z"] == 0.0 for p in payload["points"]))
        self.assertEqual(payload["explained_variance"][2], 0.0)

    def test_identical_vectors(self):
        payload = self._pca([(f"i{n}", [1.0, 1.0, 1.0], {}) for n in range(4)])
        self.assert_finite(payload)
        self.assertEqual(payload["explained_variance"], [0.0, 0.0, 0.0])

    def test_empty_payload_is_valid(self):
        self.assertEqual(empty_pca_payload()["explained_variance"], [0.0, 0.0, 0.0])
        with patch_collection(None):
            self.assertEqual(CampaignQueryService().get_pca(10), empty_pca_payload())


class CampaignEndpointTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.cert = User.objects.create_user("cert-camp@meridian.example", password="x")
        self.cert.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.client.force_authenticate(self.cert)

    def test_pca_endpoint_serializes_z_and_date(self):
        rows = [(f"r{i}", [float(i), float(i % 3), float(i % 2)],
                 {"sent_date": "2026-10-02T00:00:00Z"}) for i in range(5)]
        with patch_collection(FakeCollection(rows)):
            resp = self.client.get("/api/campaigns/pca/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["explained_variance"]), 3)
        self.assertIn("z", resp.data["points"][0])
        self.assertEqual(resp.data["points"][0]["date"], "2026-10-02")

    def test_counts_four_buckets_without_folding(self):
        labels = ["safe", "UNWANTED", "suspicious", "SUSPICIOUS", "dangerous", "weird", None]
        rows = [(f"c{i}", None, {"classification": c}) for i, c in enumerate(labels)]
        with patch_collection(FakeCollection(rows)):
            resp = self.client.get("/api/campaigns/classification-counts/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            dict(resp.data), {"SAFE": 1, "UNWANTED": 1, "SUSPICIOUS": 2, "DANGEROUS": 1}
        )

    def test_counts_empty_store(self):
        with patch_collection(None):
            resp = self.client.get("/api/campaigns/classification-counts/")
        self.assertEqual(
            dict(resp.data), {"SAFE": 0, "UNWANTED": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
        )

    def test_mail_volume_days_validation(self):
        with patch_collection(None):
            for bad in (6, 91, "x"):
                resp = self.client.get("/api/campaigns/mail-volume/", {"days": bad})
                self.assertEqual(resp.status_code, 400, bad)
            self.assertEqual(len(self.client.get("/api/campaigns/mail-volume/").data["dates"]), 15)
            for good in (7, 90):
                resp = self.client.get("/api/campaigns/mail-volume/", {"days": good})
                self.assertEqual(len(resp.data["dates"]), good)

    def test_mail_volume_counts_and_clamps_to_period(self):
        now = datetime.now(timezone.utc)

        def iso(d):
            return (now - timedelta(days=d)).isoformat()

        rows = [
            ("a", None, {"sent_date": iso(0), "classification": "DANGEROUS", "sourceRefs": ["x"]}),
            ("b", None, {"sent_date": iso(5), "classification": "SAFE", "sourceRefs": ["x"]}),
            ("c", None, {"sent_date": iso(20), "classification": "SAFE", "sourceRefs": ["x"]}),
        ]
        with patch_collection(FakeCollection(rows)):
            resp = self.client.get("/api/campaigns/mail-volume/", {"days": 7})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(sum(resp.data["dangerous"]), 1)
        self.assertEqual(sum(resp.data["non_danger"]), 1)
        band = resp.data["campaigns"][0]
        self.assertTrue(band["start"].startswith(resp.data["dates"][0]))

    def test_mail_volume_cached_per_days_not_on_failure(self):
        with patch_collection(FakeCollection([])) as getter:
            self.client.get("/api/campaigns/mail-volume/")
            self.client.get("/api/campaigns/mail-volume/")
            self.client.get("/api/campaigns/mail-volume/", {"days": 30})
        self.assertEqual(getter.call_count, 2)

        cache.clear()

        def exploding(_collection):
            yield {"sent_date": datetime.now(timezone.utc).isoformat()}
            raise RuntimeError("chroma went away")

        with patch_collection(FakeCollection([])), mock.patch(
            "api.services.campaigns.service.iter_metadata_dicts", exploding
        ):
            resp = self.client.get("/api/campaigns/mail-volume/")
        self.assertEqual(sum(resp.data["non_danger"]), 0)
        self.assertIsNone(cache.get("campaigns:mail-volume:15"))
