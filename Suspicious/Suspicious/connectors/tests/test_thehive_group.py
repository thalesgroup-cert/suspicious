from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from connectors.contrib.thehive.connector import TheHiveConnector
from connectors.contrib.thehive.phishing import build_group_observables
from ip_process.models import IP


class ThehiveGroupObservablesTests(TestCase):
    def _group_case(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        for a in ("8.8.8.8", "1.1.1.1"):
            ObservableGroupArtifact.objects.create(
                group=g, artifact_type="IP", ip=IP.objects.create(address=a)
            )
        return Case.objects.create(description="d", reporter=u, observable_group=g)

    def test_builds_one_observable_per_target(self):
        case = self._group_case()
        obs = build_group_observables(case)
        self.assertEqual(sorted(o["data"] for o in obs), ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(all(o["dataType"] == "ip" for o in obs))

    def test_on_case_finalised_creates_alert_with_observables(self):
        case = self._group_case()
        connector = TheHiveConnector({"url": "https://hive", "api_key": "k"})
        with mock.patch(
            "connectors.contrib.thehive.phishing.create_new_alert",
            return_value={"_id": "alert-1"},
        ) as cna, mock.patch(
            "connectors.contrib.thehive.phishing.add_observables_to_item"
        ) as aoi:
            connector.on_case_finalised(mock.Mock(case_id=case.id))
        cna.assert_called_once()
        aoi.assert_called_once()
        _t, _id, sent, _u, _k = aoi.call_args[0]
        self.assertEqual(_id, "alert-1")
        self.assertEqual(len(sent), 2)

    def test_on_case_finalised_skips_non_group_case(self):
        u = User.objects.create_user("u2", password="p")
        case = Case.objects.create(description="d", reporter=u)
        connector = TheHiveConnector({"url": "https://hive", "api_key": "k"})
        with mock.patch(
            "connectors.contrib.thehive.phishing.create_new_alert"
        ) as cna:
            connector.on_case_finalised(mock.Mock(case_id=case.id))
        cna.assert_not_called()
