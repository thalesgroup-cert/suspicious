from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.case_utils.case_handler import CaseHandler
from case_handler.models import Case
from domain_process.models import Domain
from ip_process.models import IP
from tasp.forms import UploadFileForm, UploadOtherForm, UploadURLForm
from url_process.models import URL


class SubmitFormsKeepContextTest(TestCase):
    def test_url_form_keeps_context(self):
        form = UploadURLForm(data={"url": "https://a.test/x", "context": "got it by SMS"})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["context"], "got it by SMS")

    def test_other_form_keeps_context(self):
        form = UploadOtherForm(data={"other": "8.8.8.8", "context": "seen in proxy logs"})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["context"], "seen in proxy logs")

    def test_file_form_keeps_context(self):
        form = UploadFileForm(
            data={"context": "attachment from CFO"},
            files={"file": SimpleUploadedFile("a.txt", b"x")},
        )
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["context"], "attachment from CFO")

    def test_context_is_optional(self):
        form = UploadURLForm(data={"url": "https://a.test/x"})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["context"], "")

    def test_context_not_truncated_at_serializer_limit(self):
        text = "a" * 2000
        form = UploadOtherForm(data={"other": "8.8.8.8", "context": text})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["context"], text)


class HandleCaseStoresContextTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="ctx_u", password="x")
        self.request = RequestFactory().post("/")
        self.request.user = self.user

    def _handler(self, **forms):
        return CaseHandler(
            self.request,
            forms.get("file_form", UploadFileForm()),
            forms.get("url_form", UploadURLForm()),
            forms.get("other_form", UploadOtherForm()),
        )

    def test_url_context_lands_on_case(self):
        handler = self._handler(
            url_form=UploadURLForm(data={"url": "https://a.test/x", "context": "got it by SMS"})
        )
        handler.url_form.is_valid()
        case = handler.handle_case(url_inst=URL.objects.create(address="https://a.test/x"))
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "got it by SMS")
        self.assertEqual(case.description, "got it by SMS")

    def test_other_context_lands_on_case(self):
        handler = self._handler(
            other_form=UploadOtherForm(data={"other": "8.8.8.8", "context": "seen in proxy logs"})
        )
        handler.other_form.is_valid()
        case = handler.handle_case(ip_inst=IP.objects.create(address="8.8.8.8"))
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "seen in proxy logs")

    def test_no_context_leaves_reporter_context_blank(self):
        handler = self._handler(url_form=UploadURLForm(data={"url": "https://a.test/x"}))
        handler.url_form.is_valid()
        case = handler.handle_case(url_inst=URL.objects.create(address="https://a.test/x"))
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "")


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmitEndpointsStoreContextTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="ctx_api", password="x")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @patch("api.views.submit.dispatch_case_analysis.delay")
    @patch("case_handler.case_utils.case_handler.URLHandler.handle_url")
    def test_submit_url_stores_context(self, handle_url, _delay):
        handle_url.return_value = (
            URL.objects.create(address="https://a.test/x"),
            Domain.objects.create(value="a.test"),
        )
        r = self.client.post(
            "/api/submit/url/",
            {"url": "https://a.test/x", "context": "got it by SMS"},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(Case.objects.get(id=r.json()["case_id"]).reporter_context, "got it by SMS")

    @patch("api.views.submit.dispatch_case_analysis.delay")
    @patch("case_handler.case_utils.case_handler.IPHandler.handle_ip")
    def test_submit_other_stores_context(self, handle_ip, _delay):
        handle_ip.return_value = IP.objects.create(address="8.8.8.8")
        r = self.client.post(
            "/api/submit/other/",
            {"value": "8.8.8.8", "context": "seen in proxy logs"},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(
            Case.objects.get(id=r.json()["case_id"]).reporter_context, "seen in proxy logs"
        )
