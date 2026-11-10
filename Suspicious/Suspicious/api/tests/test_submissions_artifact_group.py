"""The Submissions list names a multi-indicator case by its indicators, as the Investigations
list does, instead of falling back to the case description ("12 out of 14 analyzers...")."""
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from api.serializers.submissions import resolve_case_artifact
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from ip_process.models import IP


def _group_case(reporter, addresses, description="12 out of 14 analyzers ran"):
    group = ObservableGroup.objects.create()
    for address in addresses:
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="IP", ip=IP.objects.create(address=address)
        )
    return Case.objects.create(description=description, reporter=reporter, observable_group=group)


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmissionsArtifactGroupTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u", password="pw-12345")

    def test_group_case_lists_its_indicators_separated_by_commas(self):
        case = _group_case(self.user, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(resolve_case_artifact(case), "8.8.8.8, 1.1.1.1")

    def test_more_than_three_indicators_show_three_and_the_rest_as_a_count(self):
        case = _group_case(self.user, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"])
        self.assertEqual(resolve_case_artifact(case), "10.0.0.1, 10.0.0.2, 10.0.0.3 +2 more")

    def test_a_group_without_a_readable_indicator_says_how_many(self):
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="IP", ip=IP.objects.create(address="")
        )
        case = Case.objects.create(description="d", reporter=self.user, observable_group=group)
        self.assertEqual(resolve_case_artifact(case), "1 indicator(s)")

    def test_a_case_with_no_indicators_still_falls_back_to_its_description(self):
        case = Case.objects.create(description="plain description", reporter=self.user)
        self.assertEqual(resolve_case_artifact(case), "plain description")

    def test_the_submissions_list_shows_the_indicators_not_the_description(self):
        _group_case(self.user, ["8.8.8.8", "1.1.1.1"])
        client = APIClient()
        client.force_authenticate(self.user)
        body = client.get("/api/submissions/").json()
        rows = body["results"] if isinstance(body, dict) else body
        self.assertEqual(rows[0]["artifact"], "8.8.8.8, 1.1.1.1")
