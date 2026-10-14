"""Elastic SIEM forwarding: verdict filter, ECS document builder, and the HTTP
client for the target Elasticsearch. Plain ``requests``, no Elasticsearch client
library, so there is no client/server version coupling.

See docs/specs/2026-10-14-elastic-siem-connector-design.md."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
from email.utils import getaddresses
from urllib.parse import urlsplit

from django.utils import timezone

from common.http_client import make_session
from connectors.base import HealthStatus
from cortex_job.cortex_utils.case_targets import collect_case_targets

logger = logging.getLogger("connectors.contrib.elastic_siem")

DEFAULT_INDEX = "suspicious-cases-siem"
DEFAULT_MIN_VERDICT = "Suspicious"
DEFAULT_TIMEOUT = 10
HEALTH_TIMEOUT = 5
MAX_VALUE_CHARS = 512

# select_related set that makes build_document() cheap on a Case queryset.
CASE_RELATED = (
    "fileOrMail", "fileOrMail__mail", "fileOrMail__file",
    "nonFileIocs", "nonFileIocs__url", "nonFileIocs__ip", "nonFileIocs__hash",
    "observable_group",
)

# Verdict ranks. Bands absent here (Unchallenged, Failure) are never forwarded
# and never trigger an update.
RANKS = {"Safe": 0, "AllowListed": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}
MIN_VERDICTS = ("Safe", "Inconclusive", "Suspicious", "Dangerous")


class SiemError(Exception):
    """The target Elasticsearch refused or failed a request."""


# ── verdict filter ─────────────────────────────────────────────────────────

def min_rank(config: dict) -> int:
    """Rank of the configured ``min_verdict``. An unknown value is a
    configuration error, never a silent "forward everything"."""
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


def is_forwardable(case, config: dict) -> bool:
    rank = case_rank(case)
    return rank is not None and rank >= min_rank(config)


# ── document ───────────────────────────────────────────────────────────────

def _cap(value) -> str:
    return str(value)[:MAX_VALUE_CHARS]


def _dedupe(values) -> list:
    seen: dict = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)


def _prune(value):
    """Drop None, empty strings and empty containers, recursively."""
    if isinstance(value, dict):
        pruned = {k: _prune(v) for k, v in value.items()}
        return {k: v for k, v in pruned.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [v for v in (_prune(v) for v in value) if v not in (None, "", [], {})]
    return value


def _decisive_rule(case):
    explanation = case.verdict_explanation
    if isinstance(explanation, dict):
        return explanation.get("decisive_rule")
    return None


def _addresses(raw: str) -> list[str]:
    return _dedupe(addr.strip() for _name, addr in getaddresses([raw or ""]))


def _hash_algorithm(hashtype: str) -> str | None:
    normalised = (hashtype or "").lower().replace("-", "").replace("_", "").replace(" ", "")
    for algorithm in ("sha256", "sha1", "md5"):
        if algorithm in normalised:
            return algorithm
    return None


def _host(url: str) -> str | None:
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _iocs(case) -> dict:
    urls, ips, hosts, files = [], [], [], []
    hashes: list[str] = []
    by_algorithm: dict[str, list[str]] = {"md5": [], "sha1": [], "sha256": []}

    for instance, data_type in collect_case_targets(case):
        if data_type == "url":
            urls.append(_cap(instance.address))
            host = _host(instance.address)
            (ips if host and _is_ip(host) else hosts).append(host)
        elif data_type == "ip":
            ips.append(instance.address)
        elif data_type == "domain":
            hosts.append((instance.value or "").lower())
        elif data_type == "hash":
            value = (instance.value or "").lower()
            hashes.append(value)
            algorithm = _hash_algorithm(instance.hashtype)
            if algorithm:
                by_algorithm[algorithm].append(value)
        elif data_type == "file":
            files.append(os.path.basename(instance.file_path.name))

    return {
        "url": {"original": _dedupe(urls)},
        "file": {
            "name": _dedupe(_cap(f) for f in files),
            "hash": {algo: _dedupe(values) for algo, values in by_algorithm.items()},
        },
        "related": {
            "ip": _dedupe(_cap(ip) for ip in ips if ip and _is_ip(ip)),
            "hash": _dedupe(_cap(h) for h in hashes),
            "hosts": _dedupe(_cap(h) for h in hosts),
        },
    }


def _event_block(case, action: str) -> dict:
    return {
        "action": action,
        "risk_score": float(case.final_score),
    }


def _suspicious_block(case) -> dict:
    return {
        "verdict": case.results,
        "score": float(case.final_score),
        "confidence": float(case.final_confidence),
        "status": case.status,
        "decisive_rule": _decisive_rule(case),
    }


def build_document(case, action: str, ui_base_url: str = "", now=None) -> dict:
    now = now or timezone.now()
    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail_id else None

    suspicious = {"case_id": case.pk, **_suspicious_block(case)}
    if ui_base_url and ui_base_url.strip():
        suspicious["url"] = f"{ui_base_url.strip().rstrip('/')}/investigation?open={case.pk}"

    doc = {
        "@timestamp": now.isoformat(),
        "event": {
            "kind": "event",
            "category": ["email", "threat"],
            "type": ["info"],
            "module": "suspicious",
            "dataset": "suspicious.case",
            "id": str(case.pk),
            "created": case.creation_date.isoformat(),
            **_event_block(case, action),
        },
        "suspicious": suspicious,
        **_iocs(case),
    }
    if mail:
        doc["email"] = {
            "subject": _cap(mail.subject),
            "from": {"address": _addresses(mail.mail_from)},
            "to": {"address": _addresses(mail.to)},
        }
    return _prune(doc)


def build_update(case, action: str, now=None) -> dict:
    """Partial document for a verdict change on an already-forwarded case. Not
    pruned: an explicit null clears a stale ``decisive_rule``."""
    now = now or timezone.now()
    return {
        "@timestamp": now.isoformat(),
        "event": _event_block(case, action),
        "suspicious": _suspicious_block(case),
    }


# ── index mappings ─────────────────────────────────────────────────────────

def index_body() -> dict:
    keyword = {"type": "keyword"}
    text_sub = {"fields": {"text": {"type": "match_only_text"}}}
    return {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {
                    "kind": keyword, "category": keyword, "type": keyword,
                    "module": keyword, "dataset": keyword, "action": keyword, "id": keyword,
                    "created": {"type": "date"}, "risk_score": {"type": "float"},
                }},
                "suspicious": {"dynamic": False, "properties": {
                    "case_id": {"type": "long"}, "verdict": keyword,
                    "score": {"type": "float"}, "confidence": {"type": "float"},
                    "status": keyword, "decisive_rule": keyword, "url": keyword,
                }},
                "email": {"properties": {
                    "subject": {"type": "keyword", "ignore_above": 1024, **text_sub},
                    "from": {"properties": {"address": keyword}},
                    "to": {"properties": {"address": keyword}},
                }},
                "url": {"properties": {
                    "original": {"type": "keyword", "ignore_above": 2048, **text_sub},
                }},
                "file": {"properties": {
                    "name": keyword,
                    "hash": {"properties": {"md5": keyword, "sha1": keyword, "sha256": keyword}},
                }},
                "related": {"properties": {"ip": {"type": "ip"}, "hash": keyword, "hosts": keyword}},
            },
        },
    }


# ── HTTP client ────────────────────────────────────────────────────────────

def _as_bool(value, default: bool) -> bool:
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


class SiemClient:
    def __init__(self, config: dict):
        self.url, self._api_key = validate_config(config)
        self.index = (config.get("index") or DEFAULT_INDEX).strip() or DEFAULT_INDEX
        self.verify = _as_bool(config.get("verify_tls"), True)
        self.timeout = int(config.get("timeout_seconds") or DEFAULT_TIMEOUT)
        self.create_index = _as_bool(config.get("create_index"), True)
        self.session = make_session()

    # -- plumbing

    def _request(self, method: str, path: str, *, body=None, raw: bytes | None = None,
                 content_type: str = "application/json", timeout: int | None = None):
        headers = {"Authorization": f"ApiKey {self._api_key}", "Accept": "application/json"}
        data = raw
        if body is not None:
            data = json.dumps(body)
        if data is not None:
            headers["Content-Type"] = content_type
        return self.session.request(
            method, f"{self.url}{path}", headers=headers, data=data,
            timeout=timeout or self.timeout, verify=self.verify,
        )

    @staticmethod
    def _raise_for(response, what: str) -> None:
        status = response.status_code
        if 200 <= status < 300:
            return
        if status in (401, 403):
            raise SiemError(f"{what}: authentication failed (HTTP {status})")
        raise SiemError(f"{what}: HTTP {status} {(response.text or '')[:300]}")

    # -- operations

    def ensure_index(self) -> None:
        if not self.create_index:
            return
        head = self._request("HEAD", f"/{self.index}")
        if head.status_code == 200:
            return
        if head.status_code != 404:
            self._raise_for(head, "index check")
        created = self._request("PUT", f"/{self.index}", body=index_body())
        if created.status_code == 400 and "resource_already_exists_exception" in (created.text or ""):
            return  # another worker won the race
        self._raise_for(created, "index create")

    def put_case(self, case_id: int, doc: dict) -> None:
        self._raise_for(self._request("PUT", f"/{self.index}/_doc/{case_id}", body=doc), "index")

    def update_case(self, case_id: int, partial: dict) -> bool:
        """Merge ``partial`` into an existing document. False (not an error)
        when the document does not exist: the case was never forwarded."""
        response = self._request("POST", f"/{self.index}/_update/{case_id}", body={"doc": partial})
        if response.status_code == 404:
            return False
        self._raise_for(response, "update")
        return True

    def bulk(self, docs) -> tuple[int, int]:
        lines = []
        for case_id, doc in docs:
            lines.append(json.dumps({"index": {"_index": self.index, "_id": str(case_id)}}))
            lines.append(json.dumps(doc))
        payload = ("\n".join(lines) + "\n").encode()
        response = self._request("POST", "/_bulk", raw=payload, content_type="application/x-ndjson",
                                 timeout=self.timeout * 6)
        self._raise_for(response, "bulk")
        items = response.json().get("items", [])
        errors = sum(1 for item in items if item.get("index", {}).get("status", 200) >= 300)
        return len(items) - errors, errors

    def health(self) -> HealthStatus:
        try:
            response = self._request("GET", "/", timeout=HEALTH_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=f"{self.url} unreachable: {exc}")
        status = response.status_code
        if 200 <= status < 300:
            try:
                version = (response.json().get("version") or {}).get("number")
            except Exception:  # noqa: BLE001 — a non-JSON 2xx is still reachable
                version = None
            return HealthStatus(ok=True, detail=f"reachable ({self.url}{', ' + version if version else ''})")
        if status in (401, 403):
            return HealthStatus(ok=False, detail=f"authentication failed (HTTP {status})")
        return HealthStatus(ok=False, detail=f"{self.url} returned HTTP {status}")
