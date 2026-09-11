from django.test import TestCase
from django.contrib.auth.models import User

from ip_process.models import IP
from hash_process.models import Hash
from domain_process.models import Domain
from case_handler.models import (
    Case, CaseHasNonFileIocs, ObservableGroup, ObservableGroupArtifact,
)
from cortex_job.cortex_utils.case_targets import collect_case_targets


class CaseTargetsGroupTests(TestCase):
    def test_group_targets_enumerated(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="2.2.2.2")
        h = Hash.objects.create(value="a" * 64)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="HASH", hash=h)
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        targets = collect_case_targets(case)
        got = {(dt, inst.pk) for inst, dt in targets}
        self.assertEqual(got, {("ip", ip.pk), ("hash", h.pk)})

    def test_group_domain_observable_enumerated(self):
        u = User.objects.create_user("u2", password="p")
        g = ObservableGroup.objects.create()
        d = Domain.objects.create(value="evil.example")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="DOMAIN", domain=d)
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        got = {(dt, inst.pk) for inst, dt in collect_case_targets(case)}
        self.assertEqual(got, {("domain", d.pk)})

    def test_group_and_legacy_non_file_iocs_union(self):
        u = User.objects.create_user("u3", password="p")
        g = ObservableGroup.objects.create()
        group_ip = IP.objects.create(address="5.5.5.5")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=group_ip)
        case = Case.objects.create(description="d", reporter=u, observable_group=g)
        legacy_ip = IP.objects.create(address="6.6.6.6")
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=legacy_ip)
        case.nonFileIocs = iocs
        case.save()

        got = {(dt, inst.pk) for inst, dt in collect_case_targets(case)}
        self.assertEqual(got, {("ip", group_ip.pk), ("ip", legacy_ip.pk)})
