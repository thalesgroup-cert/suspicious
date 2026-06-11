from django.test import TestCase

from connectors.models import ConnectorDelivery, ConnectorState


class ConnectorModelsTest(TestCase):
    def test_state_unique_name(self):
        ConnectorState.objects.create(name="x", enabled=True)
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            ConnectorState.objects.create(name="x")

    def test_delivery_defaults(self):
        row = ConnectorDelivery.objects.create(
            connector="x", event="case_finalised", case_id=1,
            status=ConnectorDelivery.STATUS_SUCCESS,
        )
        self.assertEqual(row.attempt, 1)
        self.assertEqual(row.error, "")
        self.assertIsNotNone(row.created_at)
