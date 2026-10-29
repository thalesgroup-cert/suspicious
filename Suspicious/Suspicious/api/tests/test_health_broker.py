from unittest.mock import patch

from django.test import TestCase


class HealthBrokerProbeTest(TestCase):
    def test_broker_down_is_reported_but_not_fatal(self):
        with patch("api.views.health._check_broker", return_value=False), \
             patch("api.views.health._check_cortex", return_value=None):
            resp = self.client.get("/api/health/")
        self.assertEqual(resp.status_code, 200)
        self.assertIs(resp.json()["checks"]["broker"], False)

    def test_probe_returns_false_when_connect_raises(self):
        from api.views.health import _check_broker
        with patch("celery.current_app.connection_for_read", side_effect=OSError("down")):
            self.assertFalse(_check_broker())
