import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import hashlib
import json
import re

VENDOR = "Suspicious"
INTEGRATION_NAME = "Suspicious"

# Verdict word on an observable -> DBotScore.
OBSERVABLE_SCORE = {
    "malicious": Common.DBotScore.BAD,
    "suspicious": Common.DBotScore.SUSPICIOUS,
    "safe": Common.DBotScore.GOOD,
    "inconclusive": Common.DBotScore.NONE,
}
# Case result -> DBotScore. Allow-listed is a positive "known good"; a failed
# analysis says nothing about the artifact, so it stays unknown.
CASE_SCORE = {
    "DANGEROUS": Common.DBotScore.BAD,
    "SUSPICIOUS": Common.DBotScore.SUSPICIOUS,
    "SAFE": Common.DBotScore.GOOD,
    "ALLOW_LISTED": Common.DBotScore.GOOD,
    "INCONCLUSIVE": Common.DBotScore.NONE,
    "UNCHALLENGED": Common.DBotScore.NONE,
    "FAILURE": Common.DBotScore.NONE,
}

POLL_INTERVAL = 60  # keeps one waiting case at 60 requests/hour of the 3000/hour user limit
POLL_TIMEOUT = 1800  # a file can wait on sandbox detonation


class InvalidRequest(DemistoException):
    """Suspicious rejected the request as malformed (HTTP 400)."""


def refang(value):
    """Undo the defanging analysts and playbooks apply (hxxp, [.], ...)."""
    return (
        (value or "")
        .replace("hxxp://", "http://").replace("hxxps://", "https://")
        .replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")
        .strip().strip("<>\"'")
    )


def hash_kind(value):
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value or ""))


def build_external_ref(args, kind, fingerprint):
    """The dedupe key sent with a submission.

    An explicit ``external_ref`` wins. Otherwise, inside an incident, the key is
    derived from the incident and the artifact, so re-running a playbook task
    returns the original case instead of analysing the same artifact again.
    ``force_new`` opts out.
    """
    explicit = (args.get("external_ref") or "").strip()
    if explicit:
        return explicit
    if argToBoolean(args.get("force_new", False)):
        return ""
    incident_id = (demisto.incident() or {}).get("id")
    if not incident_id:
        return ""
    digest = hashlib.sha1(str(fingerprint).encode("utf-8")).hexdigest()[:16]  # nosec - an id, not a secret
    return f"xsoar:{incident_id}:{kind}:{digest}"


class Client(BaseClient):
    def __init__(self, base_url, token, verify, proxy, reliability=None):
        super().__init__(
            base_url=base_url.rstrip("/"),
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
        )
        self.reliability = reliability

    def _call(self, method, path, **kwargs):
        return self._http_request(method, path, error_handler=self._raise_readable, **kwargs)

    @staticmethod
    def _raise_readable(res):
        try:
            body = res.json()
            detail = body.get("detail") if isinstance(body, dict) else None
            detail = detail or json.dumps(body)
        except ValueError:
            detail = (res.text or "")[:300]
        hints = {
            401: "The API token is missing, expired or revoked.",
            403: "The account lacks the permission this call needs (investigator role for "
                 "lookup, ticket and the investigations API).",
            404: "Not found, or the case belongs to another account.",
            429: "Rate limit reached (3000 requests per hour per user). Lengthen the polling interval.",
        }
        hint = hints.get(res.status_code)
        raise (InvalidRequest if res.status_code == 400 else DemistoException)(
            f"Suspicious API error {res.status_code}: {detail}" + (f" {hint}" if hint else "")
        )

    def whoami(self):
        return self._call("GET", "/api/auth/me/")

    def submit_url(self, url, context="", external_ref=""):
        return self._call("POST", "/api/submit/url/", json_data=_body(url=url, context=context, external_ref=external_ref))

    def submit_other(self, value, context="", external_ref=""):
        return self._call("POST", "/api/submit/other/", json_data=_body(value=value, context=context, external_ref=external_ref))

    def submit_indicators(self, indicators, context="", external_ref=""):
        return self._call(
            "POST", "/api/submit/indicators/",
            json_data=_body(indicators="\n".join(indicators), context=context, external_ref=external_ref),
        )

    def submit_file(self, path, name, context="", external_ref=""):
        with open(path, "rb") as handle:
            return self._call(
                "POST", "/api/submit/file/",
                files={"file": (name, handle)},
                data=_body(context=context, external_ref=external_ref),
                timeout=120,
            )

    def get_verdict(self, case_id):
        return self._call("GET", f"/api/submissions/{case_id}/verdict/")

    def get_ticket(self, case_id):
        return self._call("GET", f"/api/submissions/{case_id}/ticket/")

    def get_report(self, case_id, fmt):
        suffix = "report.md" if fmt == "markdown" else "report/"
        return self._call("GET", f"/api/cases/{case_id}/{suffix}", resp_type="content", timeout=60)

    def challenge(self, case_id, proposed_result, reason=""):
        return self._call(
            "POST", f"/api/submissions/{case_id}/challenge/",
            json_data={"proposed_result": proposed_result, "reason": reason},
        )

    def lookup(self, kind, value):
        return self._call("GET", "/api/lookup/", params={"type": kind, "value": value})


def _body(**fields):
    """Request body without the empty optional fields."""
    return {key: value for key, value in fields.items() if value not in (None, "")}


# ---- indicators ------------------------------------------------------------

def make_indicator(kind, value, score, reliability, description=None):
    """A Common indicator carrying its DBotScore, or None for a kind with no
    indicator type (mail, file path)."""
    dbot_types = {
        "url": DBotScoreType.URL,
        "ip": DBotScoreType.IP,
        "domain": DBotScoreType.DOMAIN,
        "hash": DBotScoreType.FILE,
    }
    if kind not in dbot_types or (kind == "hash" and not hash_kind(value)):
        return None
    dbot = Common.DBotScore(
        indicator=value,
        indicator_type=dbot_types[kind],
        integration_name=INTEGRATION_NAME,
        score=score,
        reliability=reliability,
        malicious_description=description if score == Common.DBotScore.BAD else None,
    )
    if kind == "url":
        return Common.URL(url=value, dbot_score=dbot)
    if kind == "ip":
        return Common.IP(ip=value, dbot_score=dbot)
    if kind == "domain":
        return Common.Domain(domain=value, dbot_score=dbot)
    return Common.File(dbot_score=dbot, **{hash_kind(value): value})


def observable_results(observables, reliability):
    """One indicator result per observable of a finished case, so a playbook's
    indicators pick up their Suspicious verdict without extra commands."""
    results = []
    for obs in observables or []:
        verdict = obs.get("verdict", "inconclusive")
        indicator = make_indicator(
            obs.get("dataType"), obs.get("data"), OBSERVABLE_SCORE.get(verdict, Common.DBotScore.NONE),
            reliability, description=f"Suspicious verdict: {verdict}",
        )
        if indicator is not None:
            results.append(CommandResults(indicator=indicator))
    return results


# ---- commands --------------------------------------------------------------

def test_module(client):
    me = client.whoami()
    if not isinstance(me, dict) or not me.get("username"):
        raise DemistoException("Unexpected answer from /api/auth/me/. Check the URL and token.")
    return "ok"


def verdict_outputs(verdict):
    out = dict(verdict)
    if verdict.get("done"):
        out["dbot_score"] = CASE_SCORE.get(verdict.get("result"), Common.DBotScore.NONE)
    return out


def verdict_results(verdict, reliability):
    out = verdict_outputs(verdict)
    health = verdict.get("analysis_health") or {}
    row = {
        "Case": verdict.get("case_id"),
        "Result": verdict.get("result"),
        "Score": verdict.get("score"),
        "Confidence": verdict.get("confidence"),
        "Classification": verdict.get("ai_classification"),
        "Analyzers failed": health.get("failed"),
        "External ref": verdict.get("external_ref"),
    }
    main = CommandResults(
        outputs_prefix="Suspicious.Verdict",
        outputs_key_field="case_id",
        outputs=out,
        readable_output=tableToMarkdown(f"Suspicious verdict for case {verdict.get('case_id')}", row, removeNull=True),
        raw_response=verdict,
    )
    return [main] + observable_results(verdict.get("observables"), reliability)


def allowlisted_results(submission):
    return CommandResults(
        outputs_prefix="Suspicious.Verdict",
        outputs={
            "case_id": None,
            "done": True,
            "result": "ALLOW_LISTED",
            "dbot_score": Common.DBotScore.GOOD,
            "external_ref": submission.get("external_ref", ""),
        },
        readable_output="Suspicious accepted the submission without creating a case: the artifact is on an allow list.",
        raw_response=submission,
    )


def submission_results(submission):
    row = {
        "Case": submission.get("case_id"),
        "Type": submission.get("submission_type"),
        "External ref": submission.get("external_ref"),
        "Reused earlier case": submission.get("reused"),
        "Message": submission.get("message"),
    }
    return CommandResults(
        outputs_prefix="Suspicious.Submission",
        outputs_key_field="case_id",
        outputs=submission,
        readable_output=tableToMarkdown("Suspicious submission", row, removeNull=True),
        raw_response=submission,
    )


def submit_and_poll(args, client, submit):
    """Shared body of every submit command.

    First run: submit, remember the case id in the args. With ``polling`` on, each
    run then asks for the verdict until the case is done; without it the command
    returns right after the submit.
    """
    polling = argToBoolean(args.get("polling", False))
    case_id = args.get("case_id")
    partial = None

    if not case_id:
        submission = submit(args)
        if submission.get("case_id") is None:
            return PollResult(response=allowlisted_results(submission))
        case_id = str(submission["case_id"])
        args["case_id"] = case_id
        partial = submission_results(submission)
        if not polling:
            return PollResult(response=partial)

    verdict = client.get_verdict(case_id)
    if verdict.get("done") or not polling:
        return PollResult(response=([partial] if partial else []) + verdict_results(verdict, client.reliability))
    return PollResult(response=None, continue_to_poll=True, args_for_next_run=args, partial_result=partial)


def _poll_decorator(command):
    return polling_function(
        name=command, interval=POLL_INTERVAL, timeout=POLL_TIMEOUT,
        poll_message="Suspicious is still analysing the submission.",
    )


def make_submit_command(command, submit):
    @_poll_decorator(command)
    def run(args, client):
        return submit_and_poll(args, client, lambda a: submit(client, a))

    return run


def _submit_url(client, args):
    url = refang(args.get("url"))
    if not url:
        raise DemistoException("url is required.")
    return client.submit_url(url, args.get("context", ""), build_external_ref(args, "url", url))


def _submit_other(client, args):
    value = refang(args.get("value"))
    if not value:
        raise DemistoException("value is required.")
    return client.submit_other(value, args.get("context", ""), build_external_ref(args, "other", value))


def _submit_indicators(client, args):
    raw = args.get("indicators")
    chunks = raw if isinstance(raw, list) else [raw or ""]
    items = [refang(token) for chunk in chunks for token in re.split(r"[\s,;]+", str(chunk))]
    items = [item for item in items if item]
    if not items:
        raise DemistoException("indicators is required.")
    if len(items) > 100:
        raise DemistoException(f"Too many indicators ({len(items)}). Suspicious accepts at most 100 per submission.")
    ref = build_external_ref(args, "indicators", "\n".join(sorted(set(items))))
    return client.submit_indicators(items, args.get("context", ""), ref)


def _submit_file(client, args):
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required.")
    info = demisto.getFilePath(entry_id)
    path, name = info["path"], args.get("file_name") or info.get("name") or "sample"
    with open(path, "rb") as handle:
        fingerprint = hashlib.sha256(handle.read()).hexdigest()
    return client.submit_file(path, name, args.get("context", ""), build_external_ref(args, "file", fingerprint))


submit_url_command = make_submit_command("suspicious-submit-url", _submit_url)
submit_other_command = make_submit_command("suspicious-submit-other", _submit_other)
submit_indicators_command = make_submit_command("suspicious-submit-indicators", _submit_indicators)
submit_file_command = make_submit_command("suspicious-submit-file", _submit_file)


@_poll_decorator("suspicious-get-verdict")
def get_verdict_command(args, client):
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException("case_id is required.")
    verdict = client.get_verdict(case_id)
    if verdict.get("done") or not argToBoolean(args.get("polling", False)):
        return PollResult(response=verdict_results(verdict, client.reliability))
    return PollResult(response=None, continue_to_poll=True)


def get_ticket_command(client, args):
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException("case_id is required.")
    ticket = client.get_ticket(case_id)
    verdict = ticket.get("verdict") or {}
    summary = {
        "Title": ticket.get("title"),
        "Result": verdict.get("result"),
        "Score": verdict.get("score"),
        "Severity": verdict.get("severity"),
        "Recommended action": ticket.get("recommended_action"),
    }
    readable = tableToMarkdown("Suspicious ticket", summary, removeNull=True)
    readable += tableToMarkdown(
        "Observables", ticket.get("observables") or [], headers=["dataType", "data", "verdict", "score"], removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Suspicious.Ticket", outputs_key_field="case_id", outputs=ticket,
        readable_output=readable, raw_response=ticket,
    )


def get_report_command(client, args):
    case_id = args.get("case_id")
    if not case_id:
        raise DemistoException("case_id is required.")
    fmt = (args.get("format") or "markdown").lower()
    if fmt not in ("markdown", "html"):
        raise DemistoException("format must be markdown or html.")
    content = client.get_report(case_id, fmt)
    extension = "md" if fmt == "markdown" else "html"
    return fileResult(f"suspicious_case_{case_id}.{extension}", content)


def challenge_command(client, args):
    case_id = args.get("case_id")
    result = args.get("proposed_result")
    if not case_id:
        raise DemistoException("case_id is required.")
    if result not in ("Safe", "Dangerous"):
        raise DemistoException("proposed_result must be Safe or Dangerous.")
    client.challenge(case_id, result, args.get("reason", ""))
    return CommandResults(
        readable_output=f"Challenge sent for case {case_id}: an analyst will review the proposed verdict {result}.",
    )


# Reputation commands. `kind` is the Suspicious lookup type.
REPUTATION = {
    "url": ("url", "url", DBotScoreType.URL),
    "ip": ("ip", "ip", DBotScoreType.IP),
    "domain": ("domain", "domain", DBotScoreType.DOMAIN),
    "file": ("file", "hash", DBotScoreType.FILE),
}


def submit_unknown_value(client, kind, value):
    ref = f"xsoar:reputation:{kind}:{hashlib.sha1(value.encode('utf-8')).hexdigest()[:16]}"  # nosec - an id
    if kind == "url":
        return client.submit_url(value, "Submitted by a Cortex XSOAR reputation command", ref)
    if kind in ("ip", "hash"):
        return client.submit_other(value, "Submitted by a Cortex XSOAR reputation command", ref)
    return client.submit_indicators([value], "Submitted by a Cortex XSOAR reputation command", ref)


def reputation_command(client, args, command, submit_unknown):
    arg_name, kind, dbot_type = REPUTATION[command]
    results = []
    for raw in argToList(args.get(arg_name)):
        value = refang(raw)
        if kind == "hash":
            value = value.lower()
        try:
            found = client.lookup(kind, value)
        except InvalidRequest:
            # One bad value in a list must not hide the verdicts of the others.
            results.append(CommandResults(readable_output=f"{raw}: not a valid {arg_name}, skipped."))
            continue
        if not found.get("known"):
            note = "No verdict on file."
            if submit_unknown:
                submit_unknown_value(client, kind, value)
                note = "No verdict on file: submitted to Suspicious, ask again once the analysis is done."
            result = create_indicator_result_with_dbotscore_unknown(value, dbot_type, client.reliability)
            result.readable_output = f"{value}: {note}"
            results.append(result)
            continue

        verdict = found.get("verdict", "inconclusive")
        score = OBSERVABLE_SCORE.get(verdict, Common.DBotScore.NONE)
        indicator = make_indicator(kind, value, score, client.reliability, description=f"Suspicious verdict: {verdict}")
        results.append(CommandResults(
            outputs_prefix="Suspicious.Lookup",
            outputs_key_field="value",
            outputs=found,
            indicator=indicator,
            readable_output=tableToMarkdown(f"Suspicious reputation of {value}", {
                "Value": value, "Verdict": verdict, "Score": found.get("score"),
                "Confidence": found.get("confidence"), "Last analysed": found.get("last_analyzed"),
            }),
            raw_response=found,
        ))
    return results


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        credentials = params.get("credentials") or {}
        client = Client(
            base_url=params.get("url", ""),
            token=credentials.get("password", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                params.get("integration_reliability") or DBotScoreReliability.B,
            ),
        )
        submit_unknown = argToBoolean(params.get("submit_unknown", False))

        if command == "test-module":
            return_results(test_module(client))
        elif command in REPUTATION:
            return_results(reputation_command(client, args, command, submit_unknown))
        else:
            polled = {
                "suspicious-submit-url": submit_url_command,
                "suspicious-submit-other": submit_other_command,
                "suspicious-submit-indicators": submit_indicators_command,
                "suspicious-submit-file": submit_file_command,
                "suspicious-get-verdict": get_verdict_command,
            }
            plain = {
                "suspicious-get-ticket": get_ticket_command,
                "suspicious-get-report": get_report_command,
                "suspicious-challenge": challenge_command,
            }
            if command in polled:
                return_results(polled[command](args, client))
            elif command in plain:
                return_results(plain[command](client, args))
            else:
                raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
