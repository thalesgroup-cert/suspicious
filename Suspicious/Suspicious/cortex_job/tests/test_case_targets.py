from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs
from cortex_job.cortex_utils.case_targets import collect_case_targets
from hash_process.models import Hash
from ip_process.models import IP
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
