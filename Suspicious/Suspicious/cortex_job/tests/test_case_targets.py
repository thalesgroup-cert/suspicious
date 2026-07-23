from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from cortex_job.cortex_utils.case_targets import collect_case_targets
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import ArtifactIsUrl, Mail, MailArtifact
from url_process.models import URL

User = get_user_model()


class CollectCaseTargetsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="cct_user", password="pw-12345")

    def test_case_with_no_links_returns_empty(self):
        case = Case.objects.create(reporter=self.user, description="")
        self.assertEqual(collect_case_targets(case), [])

    def test_non_file_iocs_returns_url_ip_hash(self):
        case = Case.objects.create(reporter=self.user, description="")
        url = URL.objects.create(address="http://example.com")
        ip = IP.objects.create(address="1.2.3.4")
        h = Hash.objects.create(value="deadbeef")
        iocs = CaseHasNonFileIocs.objects.create(case=case, url=url, ip=ip, hash=h)
        case.nonFileIocs = iocs
        case.save()

        targets = collect_case_targets(case)

        data_types = sorted(dt for _obj, dt in targets)
        self.assertEqual(data_types, ["hash", "ip", "url"])
        by_type = {dt: obj for obj, dt in targets}
        self.assertEqual(by_type["url"].pk, url.pk)
        self.assertEqual(by_type["ip"].pk, ip.pk)
        self.assertEqual(by_type["hash"].pk, h.pk)

    def test_non_file_iocs_partial_fields_only_returns_set_ones(self):
        case = Case.objects.create(reporter=self.user, description="")
        url = URL.objects.create(address="http://example.com")
        iocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.nonFileIocs = iocs
        case.save()

        targets = collect_case_targets(case)

        self.assertEqual([dt for _obj, dt in targets], ["url"])

    def test_analyzed_url_produces_second_url_target(self):
        """A URL that has been redirect-chased (analyzed_url set) must
        surface both the original and the analyzed URL as separate "url"
        targets, so AnalyzerReports keyed on either are found."""
        case = Case.objects.create(reporter=self.user, description="")
        analyzed = URL.objects.create(address="http://final.example")
        original = URL.objects.create(address="http://redirect.example", analyzed_url=analyzed)
        iocs = CaseHasNonFileIocs.objects.create(case=case, url=original)
        case.nonFileIocs = iocs
        case.save()

        targets = collect_case_targets(case)

        url_targets = [obj for obj, dt in targets if dt == "url"]
        self.assertEqual(
            sorted(u.pk for u in url_targets),
            sorted([original.pk, analyzed.pk]),
        )

    def test_mail_artifact_duplicate_url_collapses_to_one_target(self):
        """Two MailArtifact rows on the same mail that both point (via
        ArtifactIsUrl) at the same underlying URL must collapse to a single
        "url" target, not two."""
        case = Case.objects.create(reporter=self.user, description="")
        url = URL.objects.create(address="http://dup.example")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t",
        )

        for _ in range(2):
            artifact = MailArtifact.objects.create(mail=mail, artifact_type="URL")
            link = ArtifactIsUrl.objects.create(url=url, artifact=artifact)
            artifact.artifactIsUrl = link
            artifact.save(update_fields=["artifactIsUrl"])

        file_or_mail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = file_or_mail
        case.save()

        targets = collect_case_targets(case)

        url_targets = [obj for obj, dt in targets if dt == "url"]
        self.assertEqual(len(url_targets), 1)
        self.assertEqual(url_targets[0].pk, url.pk)
