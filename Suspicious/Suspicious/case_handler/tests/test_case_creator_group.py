from django.test import TestCase
from django.contrib.auth.models import User

from ip_process.models import IP
from url_process.models import URL
from domain_process.models import Domain
from case_handler.models import ObservableGroup, ObservableGroupArtifact, CaseArtifact
from case_handler.case_utils.case_creator import CaseCreator


class CaseCreatorGroupTests(TestCase):
    def test_group_case_gets_group_and_case_artifacts(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.4.4")
        url = URL.objects.create(address="http://a.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=url)

        case = CaseCreator(u).create_case(description="d", observable_group_instance=g)

        self.assertEqual(case.observable_group_id, g.id)
        self.assertEqual(CaseArtifact.objects.filter(case=case).count(), 2)

    def test_domain_observables_skipped_for_case_artifact(self):
        u = User.objects.create_user("u2", password="p")
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="1.1.1.1")
        dom = Domain.objects.create(value="evil.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="DOMAIN", domain=dom)

        case = CaseCreator(u).create_case(description="d", observable_group_instance=g)

        self.assertEqual(case.observable_group_id, g.id)
        # only the IP row; domain has no CaseArtifact FK/choice
        self.assertEqual(CaseArtifact.objects.filter(case=case).count(), 1)

    def test_domain_only_group_still_attached_zero_artifacts(self):
        u = User.objects.create_user("u3", password="p")
        g = ObservableGroup.objects.create()
        dom = Domain.objects.create(value="only.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="DOMAIN", domain=dom)

        case = CaseCreator(u).create_case(description="d", observable_group_instance=g)

        self.assertEqual(case.observable_group_id, g.id)
        self.assertEqual(CaseArtifact.objects.filter(case=case).count(), 0)
