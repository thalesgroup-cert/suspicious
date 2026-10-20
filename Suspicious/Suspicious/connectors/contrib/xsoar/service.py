"""Cortex XSOAR forwarding: verdict filter, incident builder and the HTTP client
for the XSOAR REST API. Plain ``requests``, no XSOAR SDK.

One incident is created per case; ``ConnectorLink`` remembers which cases were
pushed. See docs/specs/2026-10-20-xsoar-connector-design.md."""
from __future__ import annotations

import json
import logging

from common.http_client import make_session
from connectors.base import HealthStatus

logger = logging.getLogger("connectors.contrib.xsoar")

DEFAULT_MIN_VERDICT = "Suspicious"
DEFAULT_SKIP_PREFIX = "xsoar:"
DEFAULT_TIMEOUT = 10
HEALTH_TIMEOUT = 5

NAME_MAX_CHARS = 250
DETAILS_MAX_CHARS = 12000
DETAILS_MAX_OBSERVABLES = 25
RATIONALE_MAX_LINES = 10

# Verdict ranks. Bands absent here (Unchallenged, Failure) are never pushed.
RANKS = {"Safe": 0, "AllowListed": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}
MIN_VERDICTS = ("Safe", "Inconclusive", "Suspicious", "Dangerous")


class XsoarError(Exception):
    """XSOAR refused or failed a request."""


# ── config ─────────────────────────────────────────────────────────────────

def as_bool(value, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "off")
    return bool(value)


def validate_config(config: dict) -> tuple[str, str]:
    """(base url, api key) or ValueError. Never echoes the key."""
    url = (config.get("url") or "").strip().rstrip("/")
    api_key = (config.get("api_key") or "").strip()
    if not url or not api_key:
        raise ValueError("url/api_key not configured")
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be http(s)")
    return url, api_key


# ── verdict filter ─────────────────────────────────────────────────────────

def min_rank(config: dict) -> int:
    """Rank of the configured ``min_verdict``. An unknown value is a
    configuration error, never a silent "push everything"."""
    value = config.get("min_verdict")
    if value is None or value == "":
        value = DEFAULT_MIN_VERDICT
    if not isinstance(value, str) or value not in MIN_VERDICTS:
        raise ValueError(
            f"min_verdict {value!r} is not valid (expected one of: {', '.join(MIN_VERDICTS)})"
        )
    return RANKS[value]


def case_rank(case) -> int | None:
    return RANKS.get(case.results)


def skip_prefix(config: dict) -> str:
    """Prefix of an ``external_ref`` that marks a case XSOAR itself submitted.
    Unset means the default; an explicitly empty value turns the check off."""
    value = config.get("skip_ref_prefix")
    return DEFAULT_SKIP_PREFIX if value is None else str(value).strip()


def originated_in_xsoar(case, config: dict) -> bool:
    """True for a case an XSOAR playbook submitted: the incident it came from
    already exists, so pushing another would duplicate it."""
    prefix = skip_prefix(config)
    return bool(prefix) and (case.external_ref or "").startswith(prefix)


# ── incident ───────────────────────────────────────────────────────────────

def defang(value: str) -> str:
    """Make a URL, domain or IP harmless to click in a ticket."""
    return (value or "").replace("http", "hxxp").replace(".", "[.]")


def _plain(value) -> str:
    """One line of inert text: no markup that could render in the incident."""
    return " ".join(str(value).replace("`", "'").replace("|", "/").split())


def _case_subject(case) -> str:
    mail = getattr(getattr(case, "fileOrMail", None), "mail", None)
    return (getattr(mail, "subject", "") or "").strip()


def build_details(case, ticket: dict, ui_base_url: str = "") -> str:
    verdict = ticket.get("verdict") or {}
    lines = [
        f"**Verdict:** {_plain(verdict.get('result'))} "
        f"(score {verdict.get('score')}, confidence {verdict.get('confidence')})",
    ]
    if verdict.get("ai_classification"):
        lines.append(f"**Classification:** {_plain(verdict['ai_classification'])}")
    threat = ticket.get("threat_classification") or {}
    if threat.get("label"):
        lines.append(f"**Threat:** {_plain(threat['label'])}")
    health = ticket.get("analysis_health") or {}
    if health.get("failed"):
        lines.append(f"**Analyzers failed:** {health['failed']} (lower confidence)")

    rationale = [r for r in (verdict.get("rationale") or []) if r][:RATIONALE_MAX_LINES]
    if rationale:
        lines += ["", "**Why:**", *(f"- {_plain(r)}" for r in rationale)]

    lines += ["", f"**Recommended action:** {_plain(ticket.get('recommended_action', ''))}"]

    observables = ticket.get("observables") or []
    if observables:
        lines += ["", "**Observables** (URLs, domains and IPs are defanged here; the raw values are in the incident's raw JSON):"]
        for obs in observables[:DETAILS_MAX_OBSERVABLES]:
            data = _plain(obs.get("data", ""))
            if obs.get("dataType") in ("url", "domain", "ip"):
                data = defang(data)
            lines.append(f"- `{data}` ({_plain(obs.get('dataType', ''))}): {_plain(obs.get('verdict', ''))}")
        if len(observables) > DETAILS_MAX_OBSERVABLES:
            lines.append(f"- ... and {len(observables) - DETAILS_MAX_OBSERVABLES} more")

    subject = _case_subject(case)
    if subject:
        lines += ["", f"**Mail subject:** {_plain(subject)}"]
    if ui_base_url and ui_base_url.strip():
        lines += ["", f"[Open in Suspicious]({ui_base_url.strip().rstrip('/')}/investigation?open={case.pk})"]
    else:
        lines += ["", f"Suspicious case #{case.pk}"]
    return "\n".join(lines)[:DETAILS_MAX_CHARS]


def build_incident(case, ticket: dict, *, incident_type: str = "", create_investigation: bool = True,
                   ui_base_url: str = "") -> dict:
    """The body of XSOAR's create-incident call for one case."""
    verdict = ticket.get("verdict") or {}
    result = verdict.get("result") or case.results
    subject = _case_subject(case)
    name = f"Suspicious case #{case.pk}: {result}" + (f" - {_plain(subject)}" if subject else "")

    labels = [
        {"type": "Suspicious case", "value": str(case.pk)},
        {"type": "Suspicious verdict", "value": str(result)},
    ]
    if case.external_ref:
        labels.append({"type": "External reference", "value": case.external_ref})

    body = {
        "name": name[:NAME_MAX_CHARS],
        "severity": verdict.get("severity", 2),
        "details": build_details(case, ticket, ui_base_url),
        "labels": labels,
        "createInvestigation": bool(create_investigation),
        "rawJSON": json.dumps(ticket, default=str),
    }
    if case.creation_date:
        body["occurred"] = case.creation_date.isoformat()
    if incident_type:
        body["type"] = incident_type
    return body


# ── client ─────────────────────────────────────────────────────────────────

class XsoarClient:
    """XSOAR 6 and 8 differ in two ways. With an ``api_key_id`` the client talks
    to XSOAR 8 (``/xsoar/public/v1/...``, ``x-xdr-auth-id`` header); without one
    it talks to XSOAR 6 (``/...``)."""

    def __init__(self, config: dict):
        self.url, self._api_key = validate_config(config)
        self.key_id = (config.get("api_key_id") or "").strip()
        self.verify = as_bool(config.get("verify_tls"), True)
        self.timeout = int(config.get("timeout_seconds") or DEFAULT_TIMEOUT)
        self.session = make_session()

    @property
    def prefix(self) -> str:
        return "/xsoar/public/v1" if self.key_id else ""

    def _request(self, method: str, path: str, *, body=None, timeout: int | None = None):
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.key_id:
            headers["x-xdr-auth-id"] = self.key_id
        return self.session.request(
            method, f"{self.url}{self.prefix}{path}", headers=headers,
            data=json.dumps(body) if body is not None else None,
            timeout=timeout or self.timeout, verify=self.verify,
        )

    @staticmethod
    def _raise_for(response, what: str) -> None:
        status = response.status_code
        if 200 <= status < 300:
            return
        if status in (401, 403):
            raise XsoarError(f"{what}: authentication failed (HTTP {status})")
        raise XsoarError(f"{what}: HTTP {status} {(response.text or '')[:300]}")

    def create_incident(self, body: dict) -> str:
        """Create an incident and return its id ("" when XSOAR did not say)."""
        response = self._request("POST", "/incident", body=body)
        self._raise_for(response, "create incident")
        try:
            return str(response.json().get("id") or "")
        except (ValueError, AttributeError):
            return ""

    def health(self) -> HealthStatus:
        try:
            response = self._request(
                "POST", "/incidents/search", body={"filter": {"page": 0, "size": 1}}, timeout=HEALTH_TIMEOUT,
            )
        except Exception as exc:  # network, TLS, DNS: report, never raise
            return HealthStatus(ok=False, detail=f"unreachable: {type(exc).__name__}")
        if response.status_code in (401, 403):
            return HealthStatus(ok=False, detail=f"authentication failed (HTTP {response.status_code})")
        if not 200 <= response.status_code < 300:
            return HealthStatus(ok=False, detail=f"HTTP {response.status_code}")
        return HealthStatus(ok=True, detail="reachable, key accepted")
