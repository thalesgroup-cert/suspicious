from unittest.mock import patch

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class IocRoadE2ETests(TestCase):
    @patch("api.views.submit.dispatch_case_analysis.delay")
    def test_submit_bulk_then_fetch_investigation_and_report(self, _delay):
        user = _make_user("u")
        client = APIClient()
        client.force_authenticate(user)

        r = client.post(
            "/api/submit/indicators/",
            {"indicators": "8.8.8.8\nhttp://a.test\n" + "a" * 64},
            format="json",
        )
        self.assertEqual(r.status_code, 201)
        case_id = r.json()["case_id"]

        case = Case.objects.get(id=case_id)
        self.assertEqual(case.observable_group.artifacts.count(), 3)

        detail = client.get(f"/api/investigations/{case_id}/").json()
        self.assertEqual(len(detail["observable_group"]["observables"]), 3)

        report = client.get(f"/api/cases/{case_id}/report/?format=html")
        self.assertEqual(report.status_code, 200)
        self.assertIn("8.8.8.8", report.content.decode())
