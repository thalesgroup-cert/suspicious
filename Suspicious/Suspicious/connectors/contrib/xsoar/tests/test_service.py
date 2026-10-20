import json
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.xsoar import service


def _ticket(**over):
    ticket = {
        "case_id": 7,
        "verdict": {
            "result": "Dangerous", "score": 92.0, "confidence": 0.8, "severity": 4,
            "ai_classification": "Phishing", "rationale": ["VirusTotal flagged the link."],
        },
        "threat_classification": {"label": "Credential phishing"},
        "analysis_health": {"failed": 0},
        "observables": [
            {"dataType": "url", "data": "https://evil.example/login", "verdict": "malicious"},
            {"dataType": "ip", "data": "8.8.8.8", "verdict": "inconclusive"},
            {"dataType": "hash", "data": "a" * 64, "verdict": "safe"},
        ],
        "recommended_action": "Block the listed observables.",
    }
    ticket.update(over)
    return ticket


def _case(**over):
    mail = SimpleNamespace(subject=over.pop("subject", ""))
    attrs = dict(
        pk=7, results="Dangerous", external_ref="",
        creation_date=None, fileOrMail=SimpleNamespace(mail=mail),
    )
    attrs.update(over)
    return SimpleNamespace(**attrs)


def _response(status=200, payload=None, text=""):
    resp = mock.Mock()
    resp.status_code = status
    resp.text = text
    if payload is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = payload
    return resp


class ConfigTests(SimpleTestCase):
    def test_validate_config(self):
        self.assertEqual(
            service.validate_config({"url": " https://x.test/ ", "api_key": " k "}), ("https://x.test", "k"),
        )
        for bad in ({}, {"url": "https://x"}, {"api_key": "k"}, {"url": "ftp://x", "api_key": "k"}):
            with self.assertRaises(ValueError):
                service.validate_config(bad)

    def test_validate_config_never_echoes_the_key(self):
        with self.assertRaises(ValueError) as ctx:
            service.validate_config({"url": "ftp://x", "api_key": "SECRET-KEY"})
        self.assertNotIn("SECRET-KEY", str(ctx.exception))

    def test_as_bool(self):
        self.assertTrue(service.as_bool(None, True))
        self.assertFalse(service.as_bool("false", True))
        self.assertFalse(service.as_bool("0", True))
        self.assertTrue(service.as_bool("yes", False))
        self.assertTrue(service.as_bool("", True))

    def test_min_rank(self):
        self.assertEqual(service.min_rank({}), 2)
        self.assertEqual(service.min_rank({"min_verdict": ""}), 2)
        self.assertEqual(service.min_rank({"min_verdict": "Dangerous"}), 3)
        self.assertEqual(service.min_rank({"min_verdict": "Safe"}), 0)
        for bad in ("dangerous", "Critical", 3):
            with self.assertRaises(ValueError):
                service.min_rank({"min_verdict": bad})

    def test_case_rank(self):
        self.assertEqual(service.case_rank(_case(results="Dangerous")), 3)
        self.assertEqual(service.case_rank(_case(results="AllowListed")), 0)
        self.assertIsNone(service.case_rank(_case(results="Failure")))
        self.assertIsNone(service.case_rank(_case(results="Unchallenged")))

    def test_skip_prefix(self):
        self.assertEqual(service.skip_prefix({}), "xsoar:")
        self.assertEqual(service.skip_prefix({"skip_ref_prefix": None}), "xsoar:")
        self.assertEqual(service.skip_prefix({"skip_ref_prefix": " soar- "}), "soar-")
        self.assertEqual(service.skip_prefix({"skip_ref_prefix": ""}), "")

    def test_originated_in_xsoar(self):
        self.assertTrue(service.originated_in_xsoar(_case(external_ref="xsoar:1042:url:ab"), {}))
        self.assertFalse(service.originated_in_xsoar(_case(external_ref="jira:1042"), {}))
        self.assertFalse(service.originated_in_xsoar(_case(external_ref=""), {}))
        self.assertTrue(service.originated_in_xsoar(_case(external_ref="soar-9"), {"skip_ref_prefix": "soar-"}))
        # an empty prefix turns the check off, it must not match everything
        self.assertFalse(service.originated_in_xsoar(_case(external_ref="xsoar:1"), {"skip_ref_prefix": ""}))


class IncidentTests(SimpleTestCase):
    def test_defang(self):
        self.assertEqual(service.defang("https://evil.example/x"), "hxxps://evil[.]example/x")
        self.assertEqual(service.defang("8.8.8.8"), "8[.]8[.]8[.]8")

    def test_body_basics(self):
        body = service.build_incident(_case(), _ticket())
        self.assertEqual(body["name"], "Suspicious case #7: Dangerous")
        self.assertEqual(body["severity"], 4)
        self.assertTrue(body["createInvestigation"])
        self.assertNotIn("type", body)
        self.assertNotIn("occurred", body)
        self.assertEqual(body["labels"], [
            {"type": "Suspicious case", "value": "7"},
            {"type": "Suspicious verdict", "value": "Dangerous"},
        ])

    def test_raw_json_carries_the_whole_ticket_with_real_values(self):
        raw = json.loads(service.build_incident(_case(), _ticket())["rawJSON"])
        self.assertEqual(raw["observables"][0]["data"], "https://evil.example/login")
        self.assertEqual(raw["case_id"], 7)

    def test_optional_fields(self):
        from django.utils import timezone
        when = timezone.now()
        body = service.build_incident(
            _case(external_ref="jira:42", creation_date=when, subject="Invoice overdue"), _ticket(),
            incident_type="Phishing", create_investigation=False,
        )
        self.assertEqual(body["type"], "Phishing")
        self.assertFalse(body["createInvestigation"])
        self.assertEqual(body["occurred"], when.isoformat())
        self.assertEqual(body["name"], "Suspicious case #7: Dangerous - Invoice overdue")
        self.assertIn({"type": "External reference", "value": "jira:42"}, body["labels"])
        self.assertIn("**Mail subject:** Invoice overdue", body["details"])

    def test_name_is_capped(self):
        body = service.build_incident(_case(subject="x" * 1000), _ticket())
        self.assertEqual(len(body["name"]), service.NAME_MAX_CHARS)

    def test_details_content(self):
        details = service.build_details(_case(), _ticket(), ui_base_url="https://sus.corp/")
        self.assertIn("**Verdict:** Dangerous (score 92.0, confidence 0.8)", details)
        self.assertIn("**Classification:** Phishing", details)
        self.assertIn("**Threat:** Credential phishing", details)
        self.assertIn("- VirusTotal flagged the link.", details)
        self.assertIn("**Recommended action:** Block the listed observables.", details)
        self.assertIn("[Open in Suspicious](https://sus.corp/investigation?open=7)", details)

    def test_details_without_ui_url_names_the_case(self):
        self.assertIn("Suspicious case #7", service.build_details(_case(), _ticket()))
        self.assertNotIn("Open in Suspicious", service.build_details(_case(), _ticket()))

    def test_details_defang_network_observables_but_not_hashes(self):
        details = service.build_details(_case(), _ticket())
        self.assertIn("`hxxps://evil[.]example/login` (url): malicious", details)
        self.assertIn("`8[.]8[.]8[.]8` (ip): inconclusive", details)
        self.assertIn(f"`{'a' * 64}` (hash): safe", details)
        self.assertNotIn("https://evil.example", details)

    def test_details_cap_observables(self):
        many = [{"dataType": "domain", "data": f"d{n}.example", "verdict": "safe"} for n in range(40)]
        details = service.build_details(_case(), _ticket(observables=many))
        self.assertIn("... and 15 more", details)
        self.assertEqual(details.count("(domain)"), service.DETAILS_MAX_OBSERVABLES)

    def test_details_neutralise_markup_in_untrusted_text(self):
        ticket = _ticket(
            observables=[{"dataType": "other", "data": "a`b|c\nd", "verdict": "x|y"}],
        )
        ticket["verdict"]["rationale"] = ["line one\nline two | cell"]
        details = service.build_details(_case(subject="Re: `rm -rf` | now"), ticket)
        self.assertNotIn("|", details)
        self.assertIn("`a'b/c d`", details)
        self.assertIn("- line one line two / cell", details)

    def test_details_are_capped(self):
        ticket = _ticket()
        ticket["verdict"]["rationale"] = ["y" * 5000] * 10
        self.assertLessEqual(len(service.build_details(_case(), ticket)), service.DETAILS_MAX_CHARS)

    def test_failed_analyzers_are_called_out(self):
        details = service.build_details(_case(), _ticket(analysis_health={"failed": 2}))
        self.assertIn("**Analyzers failed:** 2", details)


class ClientTests(SimpleTestCase):
    def _client(self, **cfg):
        client = service.XsoarClient({"url": "https://xsoar.corp", "api_key": "KEY", **cfg})
        client.session = mock.Mock()
        return client

    def test_xsoar_6_paths_and_headers(self):
        client = self._client()
        client.session.request.return_value = _response(200, {"id": "1042"})
        self.assertEqual(client.create_incident({"name": "n"}), "1042")
        args, kwargs = client.session.request.call_args
        self.assertEqual(args, ("POST", "https://xsoar.corp/incident"))
        self.assertEqual(kwargs["headers"]["Authorization"], "KEY")
        self.assertNotIn("x-xdr-auth-id", kwargs["headers"])
        self.assertEqual(json.loads(kwargs["data"]), {"name": "n"})
        self.assertIs(kwargs["verify"], True)

    def test_xsoar_8_paths_and_headers(self):
        client = self._client(url="https://api-t.xdr.us.paloaltonetworks.com/", api_key_id="12")
        client.session.request.return_value = _response(200, {"id": "9"})
        client.create_incident({"name": "n"})
        args, kwargs = client.session.request.call_args
        self.assertEqual(args[1], "https://api-t.xdr.us.paloaltonetworks.com/xsoar/public/v1/incident")
        self.assertEqual(kwargs["headers"]["x-xdr-auth-id"], "12")

    def test_verify_and_timeout_come_from_config(self):
        client = self._client(verify_tls="false", timeout_seconds=3)
        client.session.request.return_value = _response(200, {"id": "1"})
        client.create_incident({})
        kwargs = client.session.request.call_args[1]
        self.assertIs(kwargs["verify"], False)
        self.assertEqual(kwargs["timeout"], 3)

    def test_answer_without_an_id(self):
        client = self._client()
        client.session.request.return_value = _response(200, None)
        self.assertEqual(client.create_incident({}), "")
        client.session.request.return_value = _response(200, {"name": "x"})
        self.assertEqual(client.create_incident({}), "")

    def test_errors(self):
        client = self._client()
        for status in (401, 403):
            client.session.request.return_value = _response(status, text="nope KEY")
            with self.assertRaisesRegex(service.XsoarError, "authentication failed"):
                client.create_incident({})
        client.session.request.return_value = _response(500, text="boom")
        with self.assertRaisesRegex(service.XsoarError, "HTTP 500 boom"):
            client.create_incident({})

    def test_health(self):
        client = self._client()
        client.session.request.return_value = _response(200, {})
        self.assertTrue(client.health().ok)
        args, kwargs = client.session.request.call_args
        self.assertEqual(args, ("POST", "https://xsoar.corp/incidents/search"))
        self.assertEqual(kwargs["timeout"], service.HEALTH_TIMEOUT)

        client.session.request.return_value = _response(401)
        status = client.health()
        self.assertFalse(status.ok)
        self.assertIn("authentication failed", status.detail)

        client.session.request.return_value = _response(502)
        self.assertEqual(client.health().detail, "HTTP 502")

    def test_health_never_raises_or_leaks(self):
        client = self._client()
        client.session.request.side_effect = ConnectionError("https://xsoar.corp?key=KEY refused")
        status = client.health()
        self.assertFalse(status.ok)
        self.assertEqual(status.detail, "unreachable: ConnectionError")
        self.assertNotIn("KEY", status.detail)
