from django.conf import settings
from django.test import SimpleTestCase
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from api.views.cortex_webhook import CortexWebhookView
from api.views.health import HealthView


class ThrottleConfigTests(SimpleTestCase):
    def test_global_default_throttle_classes_present(self):
        classes = settings.REST_FRAMEWORK.get("DEFAULT_THROTTLE_CLASSES", ())
        self.assertIn("rest_framework.throttling.UserRateThrottle", classes)
        self.assertIn("rest_framework.throttling.AnonRateThrottle", classes)

    def test_default_rates_wired(self):
        self.assertEqual(UserRateThrottle().get_rate(), "3000/hour")
        self.assertEqual(AnonRateThrottle().get_rate(), "100/hour")

    def test_machine_endpoints_exempt_from_throttling(self):
        # A throttled cortex webhook would drop analyzer callbacks and stall
        # the pipeline; a throttled health check would break monitoring.
        self.assertEqual(CortexWebhookView.throttle_classes, [])
        self.assertEqual(HealthView.throttle_classes, [])
