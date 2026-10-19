"""A Chroma read that fails part-way must not come back as complete numbers (or be cached as such)."""
from datetime import datetime, timezone
from unittest import mock

from django.core.cache import cache
from rest_framework.test import APITestCase

from api.services.campaigns.chroma import CHROMA_PAGE_SIZE, iter_collection_pages, iter_metadata_dicts
from api.services.campaigns.neighbours import get_campaign_neighbours
from api.services.campaigns.service import CampaignQueryService
from api.services.campaigns.summary import get_campaign_summary


class FailsOnSecondPage:
    """A full first page (so the reader asks for a second), then a read error."""

    def __init__(self):
        now = datetime.now(timezone.utc).isoformat()
        self.page = [(f"m{i}", [0.1, 0.2, 0.3], {"sent_date": now, "classification": "DANGEROUS"}) for i in range(CHROMA_PAGE_SIZE)]

    def get(self, ids=None, include=None, limit=None, offset=0):
        if offset >= CHROMA_PAGE_SIZE:
            raise RuntimeError("chroma went away")
        return {
            "ids": [r[0] for r in self.page],
            "embeddings": [r[1] for r in self.page],
            "metadatas": [r[2] for r in self.page],
        }


class MidScanFailureTests(APITestCase):
    def setUp(self):
        cache.clear()

    def test_the_paged_read_raises_instead_of_ending_early(self):
        with self.assertRaises(RuntimeError):
            list(iter_collection_pages(FailsOnSecondPage(), include=["metadatas"]))
        with self.assertRaises(RuntimeError):
            list(iter_metadata_dicts(FailsOnSecondPage()))

    def test_summary_takes_its_error_path_and_is_not_cached(self):
        with mock.patch("api.services.campaigns.summary.get_chroma_collection", return_value=FailsOnSecondPage()):
            payload = get_campaign_summary(7)
        self.assertEqual(payload["messages"], 0)
        self.assertIsNone(cache.get("campaigns:summary:7"))

    def test_mail_volume_takes_its_error_path_and_is_not_cached(self):
        with mock.patch("api.services.campaigns.service.get_chroma_collection", return_value=FailsOnSecondPage()):
            payload = CampaignQueryService().get_mail_volume(15)
        self.assertEqual(sum(payload["dangerous"]), 0)
        self.assertIsNone(cache.get("campaigns:mail-volume:15"))

    def test_classification_counts_are_empty_not_partial(self):
        with mock.patch("api.services.campaigns.service.get_chroma_collection", return_value=FailsOnSecondPage()):
            counts = CampaignQueryService().get_classification_counts()
        self.assertEqual(sum(counts.values()), 0)

    def test_sampled_views_fail_closed_too(self):
        # PCA and neighbours both sample the ids with one paged scan: a half-read store would give a different
        # sample that looks whole (neighbours would then cache it).
        with mock.patch("api.services.campaigns.neighbours.get_chroma_collection", return_value=FailsOnSecondPage()):
            payload = get_campaign_neighbours(1500)
        self.assertEqual(payload["near_known_bad"], [])
        self.assertIsNone(cache.get("campaigns:neighbours:1500"))
        with mock.patch("api.services.campaigns.service.get_chroma_collection", return_value=FailsOnSecondPage()):
            pca = CampaignQueryService().get_pca(1500)
        self.assertEqual(pca["points"], [])
