"""API surface for automations (SOAR playbooks): idempotent submit via
``external_ref``, the compact verdict poll, and the stored-verdict lookup."""
from unittest.mock import patch

from django.contrib.auth.models import Group, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from domain_process.models import Domain
from hash_process.models import Hash
from ip_process.models import IP
from url_process.models import URL


def _user(username, *, investigator=False):
    u = User.objects.create_user(username=username, password="pw-12345")
    if investigator:
        u.groups.add(Group.objects.get_or_create(name="CERT")[0])
    return u


def _client(user):
    c = APIClient()
    c.force_authenticate(user)
    return c


def _report(**target):
    analyzer, _ = Analyzer.objects.get_or_create(
        name="VirusTotal_GetReport_3_1", defaults={"analyzer_cortex_id": "vt", "tier": 1},
    )
    return AnalyzerReport.objects.create(
        cortex_job_id=f"j{AnalyzerReport.objects.count()}", status="Success", analyzer=analyzer,
        level="malicious", confidence=90, score=10,
        report_summary={}, report_taxonomy={}, report_full={}, **target,
    )


# The stub URLConf used by suspicious.test_settings omits the submit routes.
@override_settings(ROOT_URLCONF="suspicious.urls")
class ExternalRefSubmitTests(TestCase):
    def setUp(self):
        self.user = _user("xsoar")
        self.client = _client(self.user)
        patcher = patch("api.views.submit.dispatch_case_analysis.delay")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _submit(self, ref, **extra):
        return self.client.post(
            "/api/submit/indicators/",
            {"indicators": "8.8.8.8\nhttp://a.test/x", "external_ref": ref, **extra},
            format="json",
        )

    def test_ref_is_stored_and_echoed(self):
        r = self._submit("xsoar:1042:abc")
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertEqual(body["external_ref"], "xsoar:1042:abc")
        self.assertFalse(body["reused"])
        self.assertEqual(Case.objects.get(id=body["case_id"]).external_ref, "xsoar:1042:abc")

    def test_resubmitting_same_ref_returns_the_original_case(self):
        first = self._submit("xsoar:1042:abc").json()
        again = self._submit("xsoar:1042:abc")
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["case_id"], first["case_id"])
        self.assertTrue(again.json()["reused"])
        self.assertEqual(Case.objects.count(), 1)

    def test_reuse_skips_validation_and_work(self):
        first = self._submit("xsoar:1:a").json()
        # A replay with a body that would otherwise be rejected still resolves.
        again = self.client.post(
            "/api/submit/indicators/",
            {"indicators": "!!!garbage!!!", "external_ref": "xsoar:1:a"}, format="json",
        )
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["case_id"], first["case_id"])

    def test_different_refs_make_different_cases(self):
        a = self._submit("xsoar:1:a").json()["case_id"]
        b = self._submit("xsoar:1:b").json()["case_id"]
        self.assertNotEqual(a, b)

    def test_ref_is_scoped_to_the_reporter(self):
        mine = self._submit("shared-ref").json()["case_id"]
        other = _client(_user("other")).post(
            "/api/submit/indicators/",
            {"indicators": "8.8.8.8", "external_ref": "shared-ref"}, format="json",
        )
        self.assertEqual(other.status_code, 201)
        self.assertNotEqual(other.json()["case_id"], mine)

    def test_no_ref_never_dedupes(self):
        for _ in range(2):
            r = self.client.post("/api/submit/indicators/", {"indicators": "8.8.8.8"}, format="json")
            self.assertEqual(r.status_code, 201)
            self.assertEqual(r.json()["external_ref"], "")
        self.assertEqual(Case.objects.count(), 2)

    def test_rejects_unsafe_characters(self):
        for bad in ("has space", "semi;colon", "new\nline", "<script>", "x" * 256):
            r = self._submit(bad)
            self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(Case.objects.count(), 0)

    @patch("case_handler.case_utils.case_handler.URLHandler.handle_url")  # tldextract needs the network
    @patch("api.serializers.submit._check_no_ssrf_ip")  # the guard resolves DNS
    def test_url_endpoint_stores_and_reuses_ref(self, _ssrf, handle_url):
        handle_url.side_effect = lambda address: (
            URL.objects.get_or_create(address=address)[0],
            Domain.objects.get_or_create(value="phish.example")[0],
        )
        r = self.client.post(
            "/api/submit/url/",
            {"url": "http://phish.example/login", "external_ref": "xsoar:7:url"}, format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        again = self.client.post(
            "/api/submit/url/",
            {"url": "http://phish.example/login", "external_ref": "xsoar:7:url"}, format="json",
        )
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["case_id"], r.json()["case_id"])
        self.assertTrue(again.json()["reused"])

    def test_other_endpoint_stores_and_reuses_ref(self):
        r = self.client.post(
            "/api/submit/other/", {"value": "8.8.4.4", "external_ref": "xsoar:7:ip"}, format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        again = self.client.post(
            "/api/submit/other/", {"value": "8.8.4.4", "external_ref": "xsoar:7:ip"}, format="json",
        )
        self.assertEqual(again.json()["case_id"], r.json()["case_id"])
        self.assertTrue(again.json()["reused"])

    def test_file_endpoint_reuses_ref_before_touching_the_upload(self):
        existing = Case.objects.create(description="d", reporter=self.user, external_ref="xsoar:7:file")
        with patch("api.views.submit.process_case") as process:
            r = self.client.post(
                "/api/submit/file/",
                {"file": SimpleUploadedFile("mail.eml", b"From: a@b\n\nhi"), "external_ref": "xsoar:7:file"},
                format="multipart",
            )
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["case_id"], existing.id)
        self.assertTrue(r.json()["reused"])
        process.assert_not_called()

    def test_file_serializer_accepts_ref_as_a_form_field(self):
        from api.serializers.submit import SubmitFileSerializer
        ser = SubmitFileSerializer(data={"file": SimpleUploadedFile("a.txt", b"x"), "external_ref": "xsoar:1:file"})
        self.assertTrue(ser.is_valid(), ser.errors)
        self.assertEqual(ser.validated_data["external_ref"], "xsoar:1:file")

    def test_list_filters_by_ref(self):
        a = self._submit("xsoar:1:a").json()["case_id"]
        self._submit("xsoar:1:b")
        r = self.client.get("/api/submissions/?external_ref=xsoar:1:a")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([row["id"] for row in r.json()["results"]], [a])
        self.assertEqual(r.json()["results"][0]["external_ref"], "xsoar:1:a")


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmissionVerdictTests(TestCase):
    def setUp(self):
        self.reporter = _user("xsoar")
        self.investigator = _user("soc", investigator=True)
        self.ip = IP.objects.create(address="8.8.8.8", ioc_level="malicious", ioc_score=9, ioc_confidence=0.8)
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="IP", ip=self.ip)
        _report(ip=self.ip)
        self.case = Case.objects.create(
            description="d", reporter=self.reporter, observable_group=group,
            external_ref="xsoar:9:z", status="On Going",
            lifecycle_state=LifecycleState.ANALYZING,
        )

    def _url(self):
        return f"/api/submissions/{self.case.id}/verdict/"

    def _finalise(self):
        Case.objects.filter(pk=self.case.pk).update(
            lifecycle_state=LifecycleState.FINALIZED, status="Done", results="Dangerous",
            final_score=92.0, final_confidence=0.8, category_ai="Phishing",
            finalized_at=timezone.now(),
        )

    def test_in_progress_has_no_verdict_yet(self):
        body = _client(self.reporter).get(self._url()).json()
        self.assertFalse(body["done"])
        self.assertEqual(body["status"], "IN_PROGRESS")
        self.assertIsNone(body["result"])
        self.assertIsNone(body["score"])
        self.assertNotIn("observables", body)
        self.assertEqual(body["external_ref"], "xsoar:9:z")

    def test_done_carries_verdict_and_observables(self):
        self._finalise()
        r = _client(self.reporter).get(self._url())
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["done"])
        self.assertEqual(body["status"], "DONE")
        self.assertEqual(body["result"], "DANGEROUS")
        self.assertEqual(body["score"], 92.0)
        self.assertEqual(body["ai_classification"], "Phishing")
        self.assertEqual(body["observables"][0]["data"], "8.8.8.8")
        self.assertEqual(body["observables"][0]["verdict"], "malicious")
        self.assertIn("failed", body["analysis_health"])

    def test_challenged_case_counts_as_done(self):
        Case.objects.filter(pk=self.case.pk).update(
            lifecycle_state=LifecycleState.CONTESTED, status="Challenged", results="Suspicious",
        )
        body = _client(self.reporter).get(self._url()).json()
        self.assertTrue(body["done"])
        self.assertEqual(body["status"], "CHALLENGED")
        self.assertEqual(body["result"], "SUSPICIOUS")

    def test_allowlisted_case_is_done_immediately(self):
        Case.objects.filter(pk=self.case.pk).update(
            lifecycle_state=LifecycleState.FINALIZED, status="Done", results="AllowListed",
            is_allowlisted=True,
        )
        body = _client(self.reporter).get(self._url()).json()
        self.assertTrue(body["done"])
        self.assertEqual(body["result"], "ALLOW_LISTED")
        self.assertTrue(body["is_allowlisted"])

    def test_investigator_can_read_anyones_case(self):
        self.assertEqual(_client(self.investigator).get(self._url()).status_code, 200)

    def test_other_reporter_gets_404(self):
        self.assertEqual(_client(_user("nosy")).get(self._url()).status_code, 404)

    def test_requires_auth(self):
        self.assertIn(APIClient().get(self._url()).status_code, (401, 403))

    def test_unknown_case_is_404(self):
        self.assertEqual(_client(self.reporter).get("/api/submissions/999999/verdict/").status_code, 404)

    def test_ticket_carries_external_ref(self):
        r = _client(self.investigator).get(f"/api/submissions/{self.case.id}/ticket/")
        self.assertEqual(r.json()["external_ref"], "xsoar:9:z")


@override_settings(ROOT_URLCONF="suspicious.urls")
class ObservableLookupTests(TestCase):
    def setUp(self):
        self.investigator = _user("soc", investigator=True)
        self.client = _client(self.investigator)

    def _get(self, kind, value, client=None):
        return (client or self.client).get("/api/lookup/", {"type": kind, "value": value})

    def test_requires_investigator(self):
        r = self._get("ip", "8.8.8.8", client=_client(_user("plain")))
        self.assertEqual(r.status_code, 403)

    def test_requires_auth(self):
        self.assertIn(APIClient().get("/api/lookup/", {"type": "ip", "value": "8.8.8.8"}).status_code, (401, 403))

    def test_unknown_value_is_not_known(self):
        r = self._get("ip", "8.8.8.8")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"type": "ip", "value": "8.8.8.8", "known": False})

    def test_row_without_reports_is_not_known(self):
        # ioc_level defaults to "info": that is "never analyzed", not a verdict.
        IP.objects.create(address="8.8.8.8")
        self.assertFalse(self._get("ip", "8.8.8.8").json()["known"])

    def test_analyzed_ip(self):
        ip = IP.objects.create(address="8.8.8.8", ioc_level="malicious", ioc_score=9, ioc_confidence=0.8)
        _report(ip=ip)
        body = self._get("ip", "8.8.8.8").json()
        self.assertTrue(body["known"])
        self.assertEqual(body["verdict"], "malicious")
        self.assertEqual(body["score"], 9)
        self.assertIn("last_analyzed", body)

    def test_analyzed_url_accepts_defanged_input(self):
        url = URL.objects.create(address="http://evil.example/x", ioc_level="suspicious", ioc_score=6)
        _report(url=url)
        body = self._get("url", "hxxp://evil[.]example/x").json()
        self.assertTrue(body["known"])
        self.assertEqual(body["value"], "http://evil.example/x")
        self.assertEqual(body["verdict"], "suspicious")

    def test_analyzed_domain(self):
        dom = Domain.objects.create(value="evil.example", ioc_level="safe", ioc_score=1)
        _report(domain=dom)
        self.assertEqual(self._get("domain", "evil.example").json()["verdict"], "safe")

    def test_hash_is_matched_case_insensitively(self):
        value = "a" * 64
        h = Hash.objects.create(value=value, ioc_level="critical", ioc_score=10)
        _report(hash=h)
        body = self._get("hash", value.upper()).json()
        self.assertTrue(body["known"])
        self.assertEqual(body["verdict"], "malicious")

    def test_newest_analyzed_row_wins_over_a_newer_empty_one(self):
        old = IP.objects.create(address="8.8.8.8", ioc_level="malicious", ioc_score=9)
        _report(ip=old)
        IP.objects.create(address="8.8.8.8")  # newer duplicate, never analyzed
        self.assertEqual(self._get("ip", "8.8.8.8").json()["verdict"], "malicious")

    def test_validation(self):
        self.assertEqual(self._get("nope", "8.8.8.8").status_code, 400)
        self.assertEqual(self._get("ip", "not-an-ip").status_code, 400)
        self.assertEqual(self._get("ip", "").status_code, 400)
        # type and value must agree
        self.assertEqual(self._get("url", "8.8.8.8").status_code, 400)
        # exactly one indicator
        self.assertEqual(self._get("ip", "8.8.8.8 1.1.1.1").status_code, 400)
