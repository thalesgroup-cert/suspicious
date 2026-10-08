from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from connectors.contrib.thehive.connector import TheHiveConnector
from connectors.contrib.thehive.phishing import build_group_observables
from ip_process.models import IP


class ThehiveGroupObservablesTests(TestCase):
    def _group_case(self, results="Inconclusive"):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        for a in ("8.8.8.8", "1.1.1.1"):
            ObservableGroupArtifact.objects.create(
                group=g, artifact_type="IP", ip=IP.objects.create(address=a)
            )
        return Case.objects.create(
            description="d", reporter=u, observable_group=g, results=results
        )

    def test_builds_one_observable_per_target(self):
        case = self._group_case()
        obs = build_group_observables(case)
        self.assertEqual(sorted(o["data"] for o in obs), ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(all(o["dataType"] == "ip" for o in obs))

    def test_thehive_no_longer_subscribes_to_case_finalised(self):
        """IOC-group cases no longer get an automatic alert: TheHive only
        receives them when an analyst presses the push button."""
        from connectors.registry import registry

        self.assertNotIn("thehive", registry.subscribers("case_finalised"))
        self.assertNotIn("on_case_finalised", vars(TheHiveConnector))
