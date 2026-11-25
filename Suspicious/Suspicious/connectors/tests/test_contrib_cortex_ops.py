from types import SimpleNamespace
from unittest import mock

import pybreaker
from cortex4py.exceptions import (
    AuthenticationError,
    InvalidInputError,
    NotFoundError,
    ServerError,
    ServiceUnavailableError,
)
from django.test import SimpleTestCase, override_settings

from connectors.base import CatalogEntry, FetchResult, StartResult, WebhookNotConfigured
from connectors.contrib.cortex.connector import CortexConnector

API = "cortex_job.cortex_utils.session_cortex_api.SessionCortexApi"
CONFIG = {"url": "http://cortex:9001/", "api_key": "k", "webhook_secret": "s3cret"}
ENTRY = CatalogEntry(id="a1", name="Yara_1_0", data_types=("file",))


def conn(config=None):
    return CortexConnector(config=CONFIG if config is None else config)


class CatalogTest(SimpleTestCase):
    def test_by_type(self):
        analyzer = SimpleNamespace(id="a1", name="Yara_1_0", dataTypeList=["file", "mail_body"])
        with mock.patch(API) as api:
            api.return_value.analyzers.get_by_type.return_value = [analyzer]
            out = conn().catalog(data_type="file")
        api.assert_called_once_with("http://cortex:9001", "k", proxies={"http": "", "https": ""})
        api.return_value.analyzers.get_by_type.assert_called_once_with("file")
        self.assertEqual(out, [CatalogEntry("a1", "Yara_1_0", ("file", "mail_body"))])

    def test_by_name(self):
        analyzer = SimpleNamespace(id="a1", name="Yara_1_0", dataTypeList=["file"])
        with mock.patch(API) as api:
            api.return_value.analyzers.get_by_name.return_value = analyzer
            out = conn().catalog(name="Yara_1_0")
        api.return_value.analyzers.get_by_name.assert_called_once_with("Yara_1_0")
        self.assertEqual(out, [ENTRY])

    def test_error_is_empty(self):
        with mock.patch(API) as api:
            api.return_value.analyzers.get_by_type.side_effect = ConnectionError("down")
            self.assertEqual(conn().catalog(data_type="file"), [])
            api.return_value.analyzers.get_by_name.side_effect = NotFoundError("x")
            self.assertEqual(conn().catalog(name="nope"), [])

    def test_unoffered_role_is_empty_without_an_error_log(self):
        with mock.patch(API) as api, self.assertNoLogs("connectors.contrib.cortex.connector", "WARNING"):
            api.return_value.analyzers.get_by_name.return_value = None
            self.assertEqual(conn().catalog(name="nope"), [])

    def test_unfiltered_lists_the_whole_catalogue(self):
        remote = mock.Mock(id="i1")
        remote.name = "A1"
        with mock.patch("tasp.cron.sync_cortex._fetch_all_analyzers", return_value=[remote]), mock.patch(API):
            self.assertEqual([(e.id, e.name) for e in conn().catalog()], [("i1", "A1")])


class StartTest(SimpleTestCase):
    def test_file_payload(self):
        with mock.patch(API) as api:
            api.return_value.analyzers.run_by_name.return_value = SimpleNamespace(id="j1")
            out = conn().start(ENTRY, "file", "/tmp/x")
        api.return_value.analyzers.run_by_name.assert_called_once_with(
            "Yara_1_0", {"data": "/tmp/x", "dataType": "file", "tlp": 2})
        self.assertEqual(out, StartResult(job_id="j1"))

    def test_mail_body_sent_as_file(self):
        with mock.patch(API) as api:
            api.return_value.analyzers.run_by_name.return_value = SimpleNamespace(id="j2")
            conn().start(ENTRY, "mail_body", "/tmp/b")
        self.assertEqual(api.return_value.analyzers.run_by_name.call_args[0][1]["dataType"], "file")

    def test_blank_value_skips_cortex(self):
        with mock.patch(API) as api:
            self.assertIsNone(conn().start(ENTRY, "file", "  "))
            self.assertIsNone(conn().start(ENTRY, "file", ""))
        api.assert_not_called()

    def test_rejection_and_empty_are_none(self):
        with mock.patch(API) as api:
            api.return_value.analyzers.run_by_name.side_effect = InvalidInputError("bad input")
            with self.assertLogs("connectors.contrib.cortex.connector", "WARNING"):
                self.assertIsNone(conn().start(ENTRY, "file", "v"))
            api.return_value.analyzers.run_by_name.side_effect = None
            api.return_value.analyzers.run_by_name.return_value = None
            self.assertIsNone(conn().start(ENTRY, "file", "v"))

    def test_an_outage_propagates(self):
        import requests
        for exc in (ServiceUnavailableError("down"), AuthenticationError("401"),
                    ServerError("timeout"), requests.ConnectionError("x"),
                    requests.HTTPError("503")):
            with mock.patch(API) as api, self.subTest(exc=type(exc).__name__):
                api.return_value.analyzers.run_by_name.side_effect = exc
                with self.assertRaises(type(exc)):
                    conn().start(ENTRY, "file", "v")


class ClientReuseTest(SimpleTestCase):
    def test_one_client_per_instance(self):
        with mock.patch(API) as api:
            api.return_value.analyzers.get_by_type.return_value = []
            api.return_value.analyzers.run_by_name.return_value = SimpleNamespace(id="j1")
            api.return_value.jobs.get_by_id.side_effect = NotFoundError("gone")
            c = conn()
            c.catalog(data_type="file")
            c.start(ENTRY, "file", "/tmp/x")
            c.fetch("j1")
        api.assert_called_once()


class FetchTest(SimpleTestCase):
    def test_result(self):
        job = SimpleNamespace(status="Success", dataType="file")
        report = SimpleNamespace(report={"summary": {"dataType": "file"}, "full": {"a": 1}})
        with mock.patch(API) as api:
            api.return_value.jobs.get_by_id.return_value = job
            api.return_value.jobs.get_report.return_value = report
            out = conn().fetch("j1")
        self.assertEqual(out, FetchResult("result", "Success", {"dataType": "file"}, {"a": 1}, "file"))

    def _fetch(self, job, report=None, report_exc=None):
        with mock.patch(API) as api:
            api.return_value.jobs.get_by_id.return_value = job
            if report_exc:
                api.return_value.jobs.get_report.side_effect = report_exc
            else:
                api.return_value.jobs.get_report.return_value = report
            return conn().fetch("j1")

    def test_data_type_carried_not_in_summary(self):
        job = SimpleNamespace(status="Success", dataType="file")
        out = self._fetch(job, SimpleNamespace(report={"summary": {"x": 1}, "full": {}}))
        self.assertEqual(out.data_type, "file")
        self.assertEqual(out.summary, {"x": 1})

    def test_report_not_found_is_not_gone(self):
        job = SimpleNamespace(status="Success", dataType="file")
        out = self._fetch(job, report_exc=NotFoundError("x"))
        self.assertEqual(out, FetchResult("result", "Success", None, None, "file"))

    def test_job_without_report_keeps_status(self):
        job = SimpleNamespace(status="InProgress", dataType="url")
        out = self._fetch(job, SimpleNamespace(report=None))
        self.assertEqual(out, FetchResult("result", "InProgress", None, None, "url"))

    def test_report_missing_keys_does_not_raise(self):
        job = SimpleNamespace(status="Success", dataType="file")
        out = self._fetch(job, SimpleNamespace(report={"full": {"a": 1}}))
        self.assertEqual((out.summary, out.full), (None, {"a": 1}))
        out = self._fetch(job, SimpleNamespace(report={"summary": {"a": 1}}))
        self.assertEqual((out.summary, out.full), ({"a": 1}, None))

    def test_non_dict_report_body_is_tolerated(self):
        job = SimpleNamespace(status="InProgress", dataType="url")
        out = self._fetch(job, SimpleNamespace(report=["x"]))
        self.assertEqual(out, FetchResult("result", "InProgress", None, None, "url"))

    def test_gone(self):
        with mock.patch(API) as api:
            api.return_value.jobs.get_by_id.side_effect = NotFoundError("x")
            self.assertEqual(conn().fetch("j1"), FetchResult("gone"))

    def test_unknown_on_error(self):
        with mock.patch(API) as api:
            api.return_value.jobs.get_by_id.side_effect = ConnectionError("down")
            self.assertEqual(conn().fetch("j1"), FetchResult("unknown"))

    def test_unknown_on_open_breaker(self):
        with mock.patch(API) as api:
            api.return_value.jobs.get_by_id.side_effect = pybreaker.CircuitBreakerError()
            self.assertEqual(conn().fetch("j1"), FetchResult("unknown"))


class WebhookTest(SimpleTestCase):
    def hook(self, payload, token="s3cret", config=None):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        return conn(config).webhook(headers, payload)

    def test_ok_and_alias(self):
        self.assertEqual(self.hook({"jobId": " j1 "}), ["j1"])
        self.assertEqual(self.hook({"job_id": "j2"}), ["j2"])

    def test_rejected(self):
        self.assertIsNone(self.hook({"jobId": "j"}, token="wrong"))
        self.assertIsNone(self.hook({"jobId": "j"}, token=None))

    def test_missing_job_id(self):
        self.assertEqual(self.hook({}), [])

    @override_settings(CORTEX_WEBHOOK_SECRET="fallback")
    def test_setting_fallback_and_no_secret(self):
        cfg = {"url": "u", "api_key": "k"}
        self.assertEqual(self.hook({"jobId": "j"}, token="fallback", config=cfg), ["j"])
        with override_settings(CORTEX_WEBHOOK_SECRET=""):
            with self.assertRaises(WebhookNotConfigured):
                self.hook({"jobId": "j"}, token="", config=cfg)
