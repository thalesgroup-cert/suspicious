"""The downloadable report is available to the case's own reporter, not
just investigators -- same access rule as every other submission endpoint
(api.permissions.submissions.CanAccessSubmission)."""
from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from ip_process.models import IP


def _make_user(username, groups=()):
    u = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        g, _ = Group.objects.get_or_create(name=name)
        u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class CaseReportPermissionsTests(TestCase):
    def _case(self, reporter):
        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8")
        )
        return Case.objects.create(
            description="d", reporter=reporter, observable_group=g, results="Dangerous"
        )

    def test_reporter_can_download_own_case_report(self):
        reporter = _make_user("reporter")
        case = self._case(reporter)
        client = APIClient()
        client.force_authenticate(reporter)

        resp = client.get(f"/api/cases/{case.id}/report/?format=html")
        self.assertEqual(resp.status_code, 200)

    def test_reporter_cannot_download_someone_elses_case_report(self):
        owner = _make_user("owner")
        other = _make_user("other")
        case = self._case(owner)
        client = APIClient()
        client.force_authenticate(other)

        resp = client.get(f"/api/cases/{case.id}/report/?format=html")
        self.assertEqual(resp.status_code, 403)

    def test_investigator_can_download_any_case_report(self):
        investigator = _make_user("investigator", groups=["CERT"])
        reporter = _make_user("reporter2")
        case = self._case(reporter)
        client = APIClient()
        client.force_authenticate(investigator)

        resp = client.get(f"/api/cases/{case.id}/report/?format=html")
        self.assertEqual(resp.status_code, 200)

    def test_unauthenticated_request_is_rejected(self):
        reporter = _make_user("reporter3")
        case = self._case(reporter)
        client = APIClient()

        resp = client.get(f"/api/cases/{case.id}/report/?format=html")
        self.assertIn(resp.status_code, (401, 403))
