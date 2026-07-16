import time
from datetime import datetime, timedelta
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.chromadb.connector import ChromaDBConnector, _run_with_timeout


class RunWithTimeoutTest(SimpleTestCase):
    def test_returns_result_when_fast_enough(self):
        result = _run_with_timeout(lambda: 42, timeout=1)
        self.assertEqual(result, 42)

    def test_raises_timeout_error_on_a_genuinely_slow_call(self):
        def slow():
            time.sleep(0.3)
            return "too late"

        with self.assertRaises(TimeoutError):
            _run_with_timeout(slow, timeout=0.05)


class _FakeCollection:
    def __init__(self, ids, metadatas):
        self._ids = ids
        self._metadatas = metadatas
        self.deleted_ids = None

    def get(self):
        return {"ids": self._ids, "metadatas": self._metadatas}

    def delete(self, ids):
        self.deleted_ids = ids


class _FakeClient:
    def __init__(self, collection):
        self._collection = collection
        self.heartbeat_calls = 0

    def get_collection(self, name):
        self.collection_name_requested = name
        return self._collection

    def heartbeat(self):
        self.heartbeat_calls += 1
        return 123456


class ChromaDBConnectorSyncTest(SimpleTestCase):
    def _iso(self, days_ago: int) -> str:
        dt = datetime.now() - timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")

    def test_deletes_expired_items_and_keeps_recent_ones(self):
        collection = _FakeCollection(
            ids=["old-1", "recent-1", "old-2"],
            metadatas=[
                {"detection_date": self._iso(days_ago=20)},
                {"detection_date": self._iso(days_ago=1)},
                {"detection_date": self._iso(days_ago=16)},
            ],
        )
        client = _FakeClient(collection)

        with mock.patch("common.clients.get_chroma_client", return_value=client):
            ChromaDBConnector({"threshold_days": 15}).sync()

        self.assertEqual(sorted(collection.deleted_ids), ["old-1", "old-2"])
        self.assertEqual(client.collection_name_requested, "suspicious")

    def test_no_deletion_when_nothing_expired(self):
        collection = _FakeCollection(
            ids=["recent-1"],
            metadatas=[{"detection_date": self._iso(days_ago=1)}],
        )
        client = _FakeClient(collection)

        with mock.patch("common.clients.get_chroma_client", return_value=client):
            ChromaDBConnector({"threshold_days": 15}).sync()

        self.assertIsNone(collection.deleted_ids)

    def test_uses_configured_collection_name(self):
        collection = _FakeCollection(ids=[], metadatas=[])
        client = _FakeClient(collection)

        with mock.patch("common.clients.get_chroma_client", return_value=client):
            ChromaDBConnector({"collection_name": "custom_name"}).sync()

        self.assertEqual(client.collection_name_requested, "custom_name")


class ChromaDBConnectorHealthCheckTest(SimpleTestCase):
    def test_ok_when_heartbeat_succeeds(self):
        client = _FakeClient(_FakeCollection(ids=[], metadatas=[]))

        with mock.patch("common.clients.get_chroma_client", return_value=client):
            status = ChromaDBConnector({}).health_check()

        self.assertTrue(status.ok)
        self.assertEqual(client.heartbeat_calls, 1)

    def test_not_ok_when_client_construction_raises(self):
        with mock.patch(
            "common.clients.get_chroma_client",
            side_effect=ConnectionError("no route to host"),
        ):
            status = ChromaDBConnector({}).health_check()

        self.assertFalse(status.ok)
        self.assertIn("no route to host", status.detail)

    def test_health_check_never_raises_on_timeout(self):
        def hang():
            time.sleep(0.3)

        with mock.patch("common.clients.get_chroma_client", side_effect=hang):
            status = ChromaDBConnector({"timeout_seconds": 0.05}).health_check()

        self.assertFalse(status.ok)


class ChromaDBConnectorManifestTest(SimpleTestCase):
    def test_manifest_is_valid(self):
        ChromaDBConnector.manifest.validate()

    def test_manifest_schedule_is_daily(self):
        [schedule] = ChromaDBConnector.manifest.schedules
        self.assertEqual(schedule.name, "cleanup")
        self.assertEqual(schedule.interval_seconds, 86400)

    def test_manifest_has_no_case_events(self):
        self.assertEqual(ChromaDBConnector.manifest.events, ())
