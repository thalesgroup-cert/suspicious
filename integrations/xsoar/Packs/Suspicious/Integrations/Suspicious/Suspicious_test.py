import demistomock as demisto
import pytest
from CommonServerPython import Common, DBotScoreReliability, DemistoException

import Suspicious
from Suspicious import Client

BASE = "https://suspicious.example"


@pytest.fixture
def client():
    return Client(BASE, "tok", verify=False, proxy=False, reliability=DBotScoreReliability.B)


def _verdict(**over):
    body = {
        "case_id": 42, "external_ref": "", "status": "DONE", "done": True,
        "result": "DANGEROUS", "score": 92.0, "confidence": 0.8,
        "ai_classification": "Phishing", "analysis_health": {"failed": 1},
        "observables": [
            {"dataType": "url", "data": "http://evil.example/x", "verdict": "malicious", "score": 9},
            {"dataType": "ip", "data": "8.8.8.8", "verdict": "inconclusive", "score": 5},
            {"dataType": "hash", "data": "a" * 64, "verdict": "safe", "score": 0},
            {"dataType": "domain", "data": "evil.example", "verdict": "suspicious", "score": 6},
            {"dataType": "mail", "data": "ceo@evil.example", "verdict": "malicious"},
        ],
    }
    body.update(over)
    return body


def _submission(**over):
    body = {"status": "success", "accepted": True, "submission_type": "url", "case_id": 42,
            "external_ref": "xsoar:1:url:abc", "reused": False, "message": "Submission accepted."}
    body.update(over)
    return body


# ---- helpers ---------------------------------------------------------------

def test_refang():
    assert Suspicious.refang("hxxps://evil[.]example/x") == "https://evil.example/x"
    assert Suspicious.refang("  <http://a.test>  ") == "http://a.test"
    assert Suspicious.refang(None) == ""


def test_hash_kind():
    assert Suspicious.hash_kind("a" * 32) == "md5"
    assert Suspicious.hash_kind("a" * 40) == "sha1"
    assert Suspicious.hash_kind("a" * 64) == "sha256"
    assert Suspicious.hash_kind("abc") is None


class TestExternalRef:
    def test_explicit_wins(self, mocker):
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        assert Suspicious.build_external_ref({"external_ref": " my-ref "}, "url", "x") == "my-ref"

    def test_derived_from_incident_and_artifact(self, mocker):
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        ref = Suspicious.build_external_ref({}, "url", "http://a.test")
        assert ref.startswith("xsoar:7:url:")
        assert ref == Suspicious.build_external_ref({}, "url", "http://a.test")
        assert ref != Suspicious.build_external_ref({}, "url", "http://b.test")

    def test_derived_ref_is_accepted_by_the_server_pattern(self, mocker):
        import re
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        ref = Suspicious.build_external_ref({}, "indicators", "a\nb")
        assert re.match(r"^[A-Za-z0-9._:@/+=#-]{1,255}$", ref)

    def test_force_new_skips_the_derived_ref(self, mocker):
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        assert Suspicious.build_external_ref({"force_new": "true"}, "url", "x") == ""

    def test_no_incident_means_no_ref(self, mocker):
        mocker.patch.object(demisto, "incident", return_value={})
        assert Suspicious.build_external_ref({}, "url", "x") == ""


# ---- client ----------------------------------------------------------------

class TestClient:
    def test_sends_token_and_drops_empty_fields(self, client, requests_mock):
        m = requests_mock.post(f"{BASE}/api/submit/url/", json=_submission(), status_code=201)
        client.submit_url("http://a.test", "", "")
        assert m.last_request.headers["Authorization"] == "Token tok"
        assert m.last_request.json() == {"url": "http://a.test"}

    def test_submit_indicators_joins_lines(self, client, requests_mock):
        m = requests_mock.post(f"{BASE}/api/submit/indicators/", json={"case_id": 1}, status_code=201)
        client.submit_indicators(["8.8.8.8", "http://a.test"], "ctx", "ref-1")
        assert m.last_request.json() == {"indicators": "8.8.8.8\nhttp://a.test", "context": "ctx", "external_ref": "ref-1"}

    def test_submit_file_is_multipart(self, client, requests_mock, tmp_path):
        sample = tmp_path / "mail.eml"
        sample.write_bytes(b"From: a@b\n\nhi")
        m = requests_mock.post(f"{BASE}/api/submit/file/", json=_submission(submission_type="file"), status_code=201)
        client.submit_file(str(sample), "mail.eml", "ctx", "ref-2")
        assert "multipart/form-data" in m.last_request.headers["Content-Type"]
        body = m.last_request.body
        body = body if isinstance(body, bytes) else body.read()
        assert b'name="file"; filename="mail.eml"' in body
        assert b'name="external_ref"' in body and b"ref-2" in body

    @pytest.mark.parametrize("status,needle", [
        (401, "token"), (403, "investigator"), (404, "another account"), (429, "Rate limit"),
    ])
    def test_errors_are_readable(self, client, requests_mock, status, needle):
        requests_mock.get(f"{BASE}/api/submissions/9/verdict/", status_code=status, json={"detail": "nope"})
        with pytest.raises(DemistoException) as exc:
            client.get_verdict(9)
        assert str(status) in str(exc.value)
        assert needle in str(exc.value)
        assert "nope" in str(exc.value)

    def test_report_paths(self, client, requests_mock):
        md = requests_mock.get(f"{BASE}/api/cases/5/report.md", content=b"# r")
        html = requests_mock.get(f"{BASE}/api/cases/5/report/", content=b"<h1>r</h1>")
        assert client.get_report(5, "markdown") == b"# r"
        assert client.get_report(5, "html") == b"<h1>r</h1>"
        assert md.called and html.called

    def test_base_url_trailing_slash(self, requests_mock):
        c = Client(BASE + "/", "tok", verify=False, proxy=False)
        m = requests_mock.get(f"{BASE}/api/auth/me/", json={"username": "xsoar"})
        c.whoami()
        assert m.called


def test_test_module(client, mocker):
    mocker.patch.object(client, "whoami", return_value={"username": "xsoar", "id": 3})
    assert Suspicious.test_module(client) == "ok"
    mocker.patch.object(client, "whoami", return_value={"detail": "x"})
    with pytest.raises(DemistoException):
        Suspicious.test_module(client)


# ---- verdict and indicators ------------------------------------------------

class TestVerdictResults:
    def test_dbot_score_follows_the_case_result(self):
        for result, score in (("DANGEROUS", 3), ("SUSPICIOUS", 2), ("SAFE", 1),
                              ("ALLOW_LISTED", 1), ("INCONCLUSIVE", 0), ("FAILURE", 0)):
            assert Suspicious.verdict_outputs(_verdict(result=result))["dbot_score"] == score

    def test_not_done_has_no_dbot_score(self):
        out = Suspicious.verdict_outputs({"case_id": 1, "done": False, "result": None})
        assert "dbot_score" not in out

    def test_one_indicator_per_known_observable(self, client):
        results = Suspicious.verdict_results(_verdict(), client.reliability)
        main, indicators = results[0], results[1:]
        assert main.outputs_prefix == "Suspicious.Verdict"
        assert len(indicators) == 4  # the mail address has no indicator type
        scores = {}
        for res in indicators:
            dbot = res.indicator.dbot_score
            scores[dbot.indicator] = dbot.score
        assert scores == {
            "http://evil.example/x": Common.DBotScore.BAD,
            "8.8.8.8": Common.DBotScore.NONE,
            "a" * 64: Common.DBotScore.GOOD,
            "evil.example": Common.DBotScore.SUSPICIOUS,
        }

    def test_make_indicator_rejects_odd_hash_and_unknown_kind(self, client):
        assert Suspicious.make_indicator("hash", "xyz", 3, client.reliability) is None
        assert Suspicious.make_indicator("mail", "a@b.c", 3, client.reliability) is None


# ---- submit + poll ---------------------------------------------------------

class TestSubmitAndPoll:
    def _run(self, client, args, submit=None):
        submit = submit or (lambda a: _submission())
        return Suspicious.submit_and_poll(args, client, submit)

    def test_without_polling_returns_right_after_submit(self, client, mocker):
        get = mocker.patch.object(client, "get_verdict")
        res = self._run(client, {"polling": "false"})
        assert not res.continue_to_poll
        assert res.response.outputs["case_id"] == 42
        get.assert_not_called()

    def test_polling_waits_and_keeps_the_case_id(self, client, mocker):
        mocker.patch.object(client, "get_verdict", return_value={"case_id": 42, "done": False})
        args = {"polling": "true"}
        res = self._run(client, args)
        assert res.continue_to_poll is True
        assert res.args_for_next_run["case_id"] == "42"
        assert res.partial_result.outputs["case_id"] == 42

    def test_second_run_polls_without_submitting(self, client, mocker):
        mocker.patch.object(client, "get_verdict", return_value=_verdict())
        submit = mocker.Mock()
        res = Suspicious.submit_and_poll({"polling": "true", "case_id": "42"}, client, submit)
        submit.assert_not_called()
        assert not res.continue_to_poll
        assert res.response[0].outputs["result"] == "DANGEROUS"

    def test_finished_on_first_poll_returns_submission_and_verdict(self, client, mocker):
        mocker.patch.object(client, "get_verdict", return_value=_verdict(result="SAFE"))
        res = self._run(client, {"polling": "true"})
        assert not res.continue_to_poll
        assert res.response[0].outputs_prefix == "Suspicious.Submission"
        assert res.response[1].outputs_prefix == "Suspicious.Verdict"

    def test_allowlisted_submission_has_no_case_and_is_final(self, client, mocker):
        get = mocker.patch.object(client, "get_verdict")
        res = self._run(client, {"polling": "true"}, submit=lambda a: _submission(case_id=None))
        assert not res.continue_to_poll
        assert res.response.outputs["result"] == "ALLOW_LISTED"
        assert res.response.outputs["dbot_score"] == Common.DBotScore.GOOD
        get.assert_not_called()


class TestSubmitters:
    def test_url_is_refanged_and_ref_sent(self, client, mocker):
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        sent = mocker.patch.object(client, "submit_url", return_value=_submission())
        Suspicious._submit_url(client, {"url": "hxxp://evil[.]example/x", "context": "ticket 9"})
        url, context, ref = sent.call_args.args
        assert url == "http://evil.example/x"
        assert context == "ticket 9"
        assert ref.startswith("xsoar:7:url:")

    def test_indicators_split_on_any_separator_and_cap(self, client, mocker):
        sent = mocker.patch.object(client, "submit_indicators", return_value=_submission())
        Suspicious._submit_indicators(client, {"indicators": "8.8.8.8, hxxp://a[.]test\nevil.example"})
        assert sent.call_args.args[0] == ["8.8.8.8", "http://a.test", "evil.example"]
        with pytest.raises(DemistoException, match="at most 100"):
            Suspicious._submit_indicators(client, {"indicators": [f"{n}.example" for n in range(101)]})

    def test_required_arguments(self, client):
        for fn in (Suspicious._submit_url, Suspicious._submit_other, Suspicious._submit_indicators, Suspicious._submit_file):
            with pytest.raises(DemistoException, match="required"):
                fn(client, {})

    def test_file_uses_the_war_room_path_and_hash_ref(self, client, mocker, tmp_path):
        mocker.patch.object(demisto, "incident", return_value={"id": "7"})
        sample = tmp_path / "x.eml"
        sample.write_bytes(b"hello")
        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(sample), "name": "from-war-room.eml"})
        sent = mocker.patch.object(client, "submit_file", return_value=_submission(submission_type="file"))
        Suspicious._submit_file(client, {"entry_id": "12@7"})
        path, name, _context, ref = sent.call_args.args
        assert (path, name) == (str(sample), "from-war-room.eml")
        assert ref.startswith("xsoar:7:file:")


def test_get_verdict_command_polls_until_done(client, mocker):
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported")
    mocker.patch.object(client, "get_verdict", return_value={"case_id": 1, "done": False})
    pending = Suspicious.get_verdict_command({"case_id": "1", "polling": "true"}, client)
    assert pending.scheduled_command is not None

    # without polling the current state comes straight back, finished or not
    once = Suspicious.get_verdict_command({"case_id": "1", "polling": "false"}, client)
    assert once[0].outputs["done"] is False

    mocker.patch.object(client, "get_verdict", return_value=_verdict())
    done = Suspicious.get_verdict_command({"case_id": "42", "polling": "true"}, client)
    assert done[0].outputs["done"] is True


def test_results_serialise_to_war_room_context(client):
    """to_context() is what return_results runs: it must not choke on the
    DBotScore / malicious-description wiring."""
    for res in Suspicious.verdict_results(_verdict(), client.reliability):
        entry = res.to_context()
        assert entry["Type"] is not None
    bad = Suspicious.verdict_results(_verdict(), client.reliability)[1].to_context()
    assert bad["EntryContext"]["DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor "
                                "&& val.Type == obj.Type)"][0]["Score"] == 3


def test_challenge_validates_the_verdict(client, mocker):
    sent = mocker.patch.object(client, "challenge")
    with pytest.raises(DemistoException, match="Safe or Dangerous"):
        Suspicious.challenge_command(client, {"case_id": "1", "proposed_result": "Maybe"})
    Suspicious.challenge_command(client, {"case_id": "1", "proposed_result": "Safe", "reason": "internal tool"})
    sent.assert_called_once_with("1", "Safe", "internal tool")


# ---- reputation commands ---------------------------------------------------

class TestReputation:
    def test_known_malicious_url(self, client, mocker):
        mocker.patch.object(client, "lookup", return_value={
            "type": "url", "value": "http://evil.example/x", "known": True,
            "verdict": "malicious", "score": 9, "confidence": 0.8, "last_analyzed": "2026-10-20T10:00:00",
        })
        [res] = Suspicious.reputation_command(client, {"url": "hxxp://evil[.]example/x"}, "url", submit_unknown=False)
        client.lookup.assert_called_once_with("url", "http://evil.example/x")
        assert res.indicator.dbot_score.score == Common.DBotScore.BAD
        assert res.outputs_prefix == "Suspicious.Lookup"

    def test_hash_is_lowercased_and_typed(self, client, mocker):
        mocker.patch.object(client, "lookup", return_value={"known": True, "verdict": "safe", "score": 0})
        [res] = Suspicious.reputation_command(client, {"file": "A" * 64}, "file", submit_unknown=False)
        client.lookup.assert_called_once_with("hash", "a" * 64)
        assert res.indicator.sha256 == "a" * 64
        assert res.indicator.dbot_score.score == Common.DBotScore.GOOD

    def test_invalid_value_is_skipped_not_fatal(self, client, requests_mock):
        requests_mock.get(f"{BASE}/api/lookup/", [
            {"status_code": 400, "json": {"value": ["Not a single valid ip."]}},
            {"status_code": 200, "json": {"known": True, "verdict": "malicious", "score": 9}},
        ])
        bad, good = Suspicious.reputation_command(client, {"ip": "nonsense,8.8.8.8"}, "ip", submit_unknown=False)
        assert "not a valid ip" in bad.readable_output
        assert good.indicator.dbot_score.score == Common.DBotScore.BAD

    def test_other_errors_still_fail_the_command(self, client, requests_mock):
        requests_mock.get(f"{BASE}/api/lookup/", status_code=403, json={"detail": "Not authorized."})
        with pytest.raises(DemistoException, match="403"):
            Suspicious.reputation_command(client, {"ip": "8.8.8.8"}, "ip", submit_unknown=False)

    def test_several_values(self, client, mocker):
        mocker.patch.object(client, "lookup", return_value={"known": True, "verdict": "suspicious", "score": 6})
        results = Suspicious.reputation_command(client, {"ip": "8.8.8.8,1.1.1.1"}, "ip", submit_unknown=False)
        assert [r.indicator.ip for r in results] == ["8.8.8.8", "1.1.1.1"]

    def test_unknown_is_score_zero_and_not_submitted_by_default(self, client, mocker):
        mocker.patch.object(client, "lookup", return_value={"known": False})
        sub = mocker.patch.object(Suspicious, "submit_unknown_value")
        [res] = Suspicious.reputation_command(client, {"domain": "new.example"}, "domain", submit_unknown=False)
        assert res.indicator.dbot_score.score == Common.DBotScore.NONE
        sub.assert_not_called()

    def test_unknown_is_submitted_when_enabled(self, client, mocker):
        mocker.patch.object(client, "lookup", return_value={"known": False})
        sub = mocker.patch.object(Suspicious, "submit_unknown_value")
        [res] = Suspicious.reputation_command(client, {"domain": "new.example"}, "domain", submit_unknown=True)
        sub.assert_called_once_with(client, "domain", "new.example")
        assert "submitted" in res.readable_output

    def test_submit_unknown_routes_by_kind(self, client, mocker):
        url = mocker.patch.object(client, "submit_url")
        other = mocker.patch.object(client, "submit_other")
        many = mocker.patch.object(client, "submit_indicators")
        Suspicious.submit_unknown_value(client, "url", "http://a.test")
        Suspicious.submit_unknown_value(client, "ip", "8.8.8.8")
        Suspicious.submit_unknown_value(client, "hash", "a" * 64)
        Suspicious.submit_unknown_value(client, "domain", "a.test")
        assert (url.call_count, other.call_count, many.call_count) == (1, 2, 1)
        # one reference per value, so repeated enrichment never resubmits
        ref = url.call_args.args[2]
        Suspicious.submit_unknown_value(client, "url", "http://a.test")
        assert url.call_args.args[2] == ref
