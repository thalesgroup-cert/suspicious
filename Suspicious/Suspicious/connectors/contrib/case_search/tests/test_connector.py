from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case
from connectors.base import CaseEvent
from connectors.contrib.case_search import service
from connectors.contrib.case_search.connector import CaseSearchConnector


def _event(case_id):
    return CaseEvent(
        event="case_created", case_id=case_id, status="To Do", results="Inconclusive",
        final_score=0, confidence=0, reporter_email="a@x.io", created_at="2026-10-07T00:00:00",
    )


class CaseSearchConnectorTests(TestCase):
    def test_manifest(self):
        m = CaseSearchConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(
            set(m.events), {"case_created", "case_modified", "case_finalised"}
        )

    def test_events_index_the_case(self):
        user = User.objects.create_user("alice", "alice@x.io", "pw")
        case = Case.objects.create(description="hello", reporter=user)
        client = mock.Mock()
        client.indices.exists.return_value = True
        with mock.patch.object(service, "get_client", return_value=client):
            conn = CaseSearchConnector({"index": "idx-test"})
            conn.on_case_created(_event(case.pk))
            conn.on_case_modified(_event(case.pk))
            conn.on_case_finalised(_event(case.pk))
        self.assertEqual(client.index.call_count, 3)
        kwargs = client.index.call_args.kwargs
        self.assertEqual(kwargs["index"], "idx-test")
        self.assertEqual(kwargs["id"], case.pk)
        self.assertEqual(kwargs["document"]["description"], "hello")

    def test_missing_case_is_ignored(self):
        client = mock.Mock()
        with mock.patch.object(service, "get_client", return_value=client):
            CaseSearchConnector({}).on_case_created(_event(999999))
        client.index.assert_not_called()

    def test_es_failure_raises_so_framework_retries(self):
        user = User.objects.create_user("bob", "b@x.io", "pw")
        case = Case.objects.create(description="x", reporter=user)
        client = mock.Mock()
        client.indices.exists.return_value = True
        client.index.side_effect = RuntimeError("es down")
        with mock.patch.object(service, "get_client", return_value=client):
            with self.assertRaises(RuntimeError):
                CaseSearchConnector({}).on_case_created(_event(case.pk))

    def test_health_check_never_raises(self):
        with mock.patch.object(service, "get_client", side_effect=RuntimeError("boom")):
            self.assertFalse(CaseSearchConnector({}).health_check().ok)
        client = mock.Mock()
        client.cluster.health.return_value = {"status": "yellow"}
        with mock.patch.object(service, "get_client", return_value=client):
            self.assertTrue(CaseSearchConnector({}).health_check().ok)
