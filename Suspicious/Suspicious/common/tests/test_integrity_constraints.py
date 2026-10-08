from contextlib import contextmanager

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from case_handler.models import (
    Case, CaseArtifact, CaseHasFileOrMail, CaseHasNonFileIocs,
    ObservableGroup, ObservableGroupArtifact,
)
from cortex_job.models import Analyzer
from domain_process.models import Domain
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail
from settings.models import (
    AllowListDomain, AllowListFile, AllowListIp, CampaignDomainAllowList, DenyListDomain,
)
from url_process.models import URL


@contextmanager
def rejected():
    """The block must raise IntegrityError (a savepoint keeps the test DB usable)."""
    try:
        with transaction.atomic():
            yield
    except IntegrityError:
        return
    raise AssertionError("expected IntegrityError, none raised")


class IntegrityConstraintTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("u", "u@x.io", "pw")
        cls.case = Case.objects.create(description="d", reporter=cls.user)
        cls.url = URL.objects.create(address="http://a.test/")
        cls.ip = IP.objects.create(address="1.2.3.4")
        cls.hash = Hash.objects.create(value="a" * 64)
        cls.domain = Domain.objects.create(value="a.test")
        cls.analyzer = Analyzer.objects.create(name="A", analyzer_cortex_id="a1")
        cls.mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
        )

    # --- one-target rules -------------------------------------------------
    def test_case_artifact_needs_exactly_one_target(self):
        CaseArtifact.objects.create(case=self.case, artifact_type="url", url=self.url)
        with rejected():
            CaseArtifact.objects.create(case=self.case, artifact_type="url")
        with rejected():
            CaseArtifact.objects.create(case=self.case, artifact_type="url", url=self.url, ip=self.ip)

    def test_observable_group_artifact_needs_exactly_one_target(self):
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=self.url)
        with rejected():
            ObservableGroupArtifact.objects.create(group=group, artifact_type="URL")

    def test_case_has_file_or_mail_needs_exactly_one_target(self):
        CaseHasFileOrMail.objects.create(case=self.case, mail=self.mail)
        with rejected():
            CaseHasFileOrMail.objects.create(case=self.case)

    def test_case_has_non_file_iocs_needs_exactly_one_target(self):
        CaseHasNonFileIocs.objects.create(case=self.case, hash=self.hash)   # hash-only IOC is valid
        CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        with rejected():
            CaseHasNonFileIocs.objects.create(case=self.case)
        with rejected():
            CaseHasNonFileIocs.objects.create(case=self.case, url=self.url, ip=self.ip)

    # --- Case roads ---------------------------------------------------------
    def test_roadless_and_group_only_cases_stay_valid(self):
        Case.objects.create(description="legacy, no road", reporter=self.user)
        group = ObservableGroup.objects.create()
        Case.objects.create(description="group", reporter=self.user, observable_group=group)

    def test_file_plus_hash_style_case_stays_valid(self):
        mail_bundle = CaseHasFileOrMail.objects.create(case=self.case, mail=self.mail)
        ioc_bundle = CaseHasNonFileIocs.objects.create(case=self.case, hash=self.hash)
        Case.objects.create(
            description="two roads", reporter=self.user,
            fileOrMail=mail_bundle, nonFileIocs=ioc_bundle,
        )

    def test_group_case_cannot_also_have_another_road(self):
        group = ObservableGroup.objects.create()
        bundle = CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        with rejected():
            Case.objects.create(
                description="bad", reporter=self.user, observable_group=group, nonFileIocs=bundle,
            )

    # --- allow / deny uniqueness -------------------------------------------
    def test_allow_deny_lists_reject_duplicates(self):
        for model, field, value in (
            (AllowListDomain, "domain", self.domain),
            (DenyListDomain, "domain", self.domain),
            (CampaignDomainAllowList, "domain", self.domain),
            (AllowListIp, "ip", self.ip),
            (AllowListFile, "linked_file_hash", self.hash),
        ):
            model.objects.create(user=self.user, **{field: value})
            with rejected():
                model.objects.create(user=self.user, **{field: value})

    def test_bulk_create_ignore_conflicts_still_skips_duplicates(self):
        AllowListIp.objects.create(user=self.user, ip=self.ip)
        AllowListIp.objects.bulk_create(
            [AllowListIp(user=self.user, ip=self.ip)], ignore_conflicts=True,
        )
        self.assertEqual(AllowListIp.objects.filter(ip=self.ip).count(), 1)
