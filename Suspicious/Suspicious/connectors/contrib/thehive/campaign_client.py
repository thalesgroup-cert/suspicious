"""TheHive calls for campaign alerts.

The alert, its observables and its files go up in one multipart request, so a
Community-edition TheHive (create-only) can hold the full content; later mails
of the same campaign are added with update calls.
"""
from __future__ import annotations

import json

import requests

from connectors.contrib.thehive.campaign_alert import CampaignContent, FilePart
from connectors.contrib.thehive.phishing import _thehive_request

_TIMEOUT = 120


def _request(method: str, url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", _TIMEOUT)
    return _thehive_request(method, url, **kwargs)


def _file_observable(part: FilePart, attachment: str | None, tlp: int, pap: int) -> dict:
    obs = {"dataType": "file", "message": part.message, "tags": part.tags,
           "tlp": tlp, "pap": pap, "ioc": False, "sighted": True}
    if attachment:
        obs["attachment"] = attachment
    return obs


class HiveClient:
    def __init__(self, url: str, api_key: str, verify=True):
        self.base = url.rstrip("/") + "/api/v1"
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.verify = verify

    def _call(self, method: str, path: str, **kwargs) -> requests.Response:
        return _request(method, self.base + path, headers=self.headers, verify=self.verify, **kwargs)

    def _query(self, steps: list[dict]):
        return self._call("POST", "/query", json={"query": steps}).json()

    def create_alert(self, content: CampaignContent) -> dict:
        observables = list(content.observables)
        files = {}
        for i, part in enumerate(content.files):
            observables.append(_file_observable(part, f"file{i}", content.tlp, content.pap))
            files[f"file{i}"] = (part.filename, part.data)
        alert = {
            "type": "Suspicious", "source": "suspicious", "sourceRef": content.source_ref,
            "title": content.title, "description": content.description,
            "severity": content.severity, "tlp": content.tlp, "pap": content.pap,
            "tags": content.tags, "customFields": {"tha-id": content.source_ref},
            "observables": observables,
        }
        files["_json"] = (None, json.dumps(alert), "application/json")
        try:
            return self._call("POST", "/alert", files=files).json()
        except requests.HTTPError as exc:
            # Alerts are unique on (type, source, sourceRef): a retry after a
            # response was lost must reuse the alert it already created.
            existing = self.find_by_source_ref(content.source_ref) if _is_client_error(exc) else None
            if existing:
                return existing
            raise

    def find_by_source_ref(self, ref: str) -> dict | None:
        found = self._query([
            {"_name": "listAlert"},
            {"_name": "filter", "_eq": {"_field": "sourceRef", "_value": ref}},
        ])
        return found[0] if found else None

    def get_alert(self, alert_id: str) -> dict | None:
        try:
            return self._call("GET", f"/alert/{alert_id}").json()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise

    def list_observables(self, alert_id: str) -> list[dict]:
        return self._query([{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}])

    def add_observable(self, alert_id: str, observable: dict) -> None:
        self._call("POST", f"/alert/{alert_id}/observable", json=observable)

    def add_file_observable(self, alert_id: str, part: FilePart, tlp: int = 2, pap: int = 2) -> None:
        meta = _file_observable(part, None, tlp, pap)
        self._call("POST", f"/alert/{alert_id}/observable", files={
            "_json": (None, json.dumps(meta), "application/json"),
            "attachment": (part.filename, part.data),
        })

    def patch_alert(self, alert_id: str, fields: dict) -> None:
        self._call("PATCH", f"/alert/{alert_id}", json=fields)

    def add_comment(self, alert_id: str, message: str) -> None:
        self._call("POST", f"/alert/{alert_id}/comment", json={"message": message})


def _is_client_error(exc: requests.HTTPError) -> bool:
    status = getattr(exc.response, "status_code", 0)
    return 400 <= status < 500 and status != 403
