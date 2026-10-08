import json
from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase

from connectors.contrib.thehive.campaign_alert import CampaignContent, FilePart
from connectors.contrib.thehive.campaign_client import HiveClient

REQ = "connectors.contrib.thehive.campaign_client._request"


def _content():
    return CampaignContent(
        title="T", description="D", severity=3, tlp=2, pap=2, tags=["a"], source_ref="CAMP-1",
        observables=[{"dataType": "url", "data": "https://x.example", "message": "m", "tags": [], "tlp": 2,
                      "pap": 2, "ioc": True, "sighted": True}],
        files=[FilePart("notice.pdf", b"%PDF", "an attachment", ["attachment"]),
               FilePart("m.eml", b"From: x", "source", ["mail-source"])],
    )


def _resp(payload, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = payload
    r.text = json.dumps(payload)
    return r


def _http_error(status, text=""):
    resp = MagicMock(status_code=status, text=text)
    return requests.HTTPError(response=resp)


class CreateAlertTest(SimpleTestCase):
    def test_one_multipart_call_carries_alert_observables_and_files(self):
        with patch(REQ, return_value=_resp({"_id": "~1"})) as req:
            alert = HiveClient("http://hive", "k", verify="/etc/ca.pem").create_alert(_content())
        self.assertEqual(alert["_id"], "~1")
        method, url = req.call_args.args[:2]
        self.assertEqual((method, url), ("POST", "http://hive/api/v1/alert"))
        files = req.call_args.kwargs["files"]
        meta = json.loads(files["_json"][1])
        self.assertEqual((meta["sourceRef"], meta["type"], meta["source"], meta["severity"]),
                         ("CAMP-1", "Suspicious", "suspicious", 3))
        file_obs = [o for o in meta["observables"] if o["dataType"] == "file"]
        self.assertEqual([o["attachment"] for o in file_obs], ["file0", "file1"])
        self.assertEqual(files["file0"][0], "notice.pdf")
        self.assertEqual(files["file0"][1], b"%PDF")
        self.assertEqual(len([o for o in meta["observables"] if o["dataType"] == "url"]), 1)

    def test_certificate_path_is_passed_through_not_coerced(self):
        with patch(REQ, return_value=_resp({"_id": "~1"})) as req:
            HiveClient("http://hive", "k", verify="/etc/private/rootcafile.pem").create_alert(_content())
        self.assertEqual(req.call_args.kwargs["verify"], "/etc/private/rootcafile.pem")

    def test_an_already_created_alert_is_reused(self):
        calls = iter([_http_error(400, "already exists"), _resp([{"_id": "~9", "sourceRef": "CAMP-1"}])])

        def fake(method, url, **kw):
            result = next(calls)
            if isinstance(result, Exception):
                raise result
            return result

        with patch(REQ, side_effect=fake):
            self.assertEqual(HiveClient("http://hive", "k").create_alert(_content())["_id"], "~9")

    def test_other_errors_propagate(self):
        with patch(REQ, side_effect=_http_error(403, "no permission")):
            with self.assertRaises(requests.HTTPError):
                HiveClient("http://hive", "k").create_alert(_content())


class ReadWriteTest(SimpleTestCase):
    def test_missing_alert_is_none(self):
        with patch(REQ, side_effect=_http_error(404)):
            self.assertIsNone(HiveClient("http://hive", "k").get_alert("~gone"))

    def test_observables_are_listed_through_the_query_api(self):
        with patch(REQ, return_value=_resp([{"dataType": "url", "data": "u"}])) as req:
            obs = HiveClient("http://hive", "k").list_observables("~1")
        self.assertEqual(obs, [{"dataType": "url", "data": "u"}])
        body = req.call_args.kwargs["json"]["query"]
        self.assertEqual([step["_name"] for step in body], ["getAlert", "observables"])

    def test_file_observable_is_a_multipart_upload(self):
        with patch(REQ, return_value=_resp([])) as req:
            HiveClient("http://hive", "k").add_file_observable("~1", FilePart("a.pdf", b"%PDF", "msg", ["t"]))
        self.assertEqual(req.call_args.args[1], "http://hive/api/v1/alert/~1/observable")
        files = req.call_args.kwargs["files"]
        self.assertEqual(files["attachment"][0:2], ("a.pdf", b"%PDF"))
        self.assertEqual(json.loads(files["_json"][1])["dataType"], "file")


class AttachmentsTest(SimpleTestCase):
    """Files are also attached to the alert itself (its Attachments tab), not
    only added as file observables. TheHive rejects a name already on the alert."""

    def _fake(self, existing=(), reject=()):
        posted = []

        def fake(method, url, **kw):
            if url.endswith("/query"):
                return _resp([{"name": n} for n in existing])
            name = kw["files"][0][1][0]
            if name in reject:
                raise _http_error(400, f"File {name} already exists")
            posted.append((url, name, kw["files"][0][1][1]))
            return _resp({"attachments": [{"name": name}]}, 201)
        return fake, posted

    def test_attaches_only_files_not_already_on_the_alert(self):
        fake, posted = self._fake(existing=["notice.pdf"])
        with patch(REQ, side_effect=fake):
            added, present, failed = HiveClient("http://hive", "k").add_attachments("~1", _content().files)
        self.assertEqual((added, present, failed), (1, 1, []))
        self.assertEqual(posted, [("http://hive/api/v1/alert/~1/attachments", "m.eml", b"From: x")])

    def test_a_rejected_file_is_reported_and_the_others_still_go(self):
        fake, posted = self._fake(reject=["notice.pdf"])
        with patch(REQ, side_effect=fake):
            added, present, failed = HiveClient("http://hive", "k").add_attachments("~1", _content().files)
        self.assertEqual((added, present), (1, 0))
        self.assertEqual([name for _u, name, _d in posted], ["m.eml"])
        self.assertEqual(len(failed), 1)
        self.assertIn("notice.pdf", failed[0])

    def test_nothing_to_attach_makes_no_upload_call(self):
        fake, posted = self._fake()
        with patch(REQ, side_effect=fake):
            self.assertEqual(HiveClient("http://hive", "k").add_attachments("~1", []), (0, 0, []))
        self.assertEqual(posted, [])
