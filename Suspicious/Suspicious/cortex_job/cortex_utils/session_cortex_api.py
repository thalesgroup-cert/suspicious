"""
Cortex API wrapper backed by a shared requests.Session.

Vanilla cortex4py.api.Api calls module-level `requests.get/post/...` for
every operation: no connection pool, no TLS reuse, and — critically —
no socket-level timeout. The pybreaker/tenacity layer above only
catches exceptions after the bare call has already hung.

SessionCortexApi keeps cortex4py's controllers (which delegate via
do_get/do_post/...) and replaces the transport with a Session mounted
on common.http_client.TimeoutHTTPAdapter so connect/read timeouts and
keep-alive are guaranteed.
"""
from __future__ import annotations

from cortex4py.api import Api

from common.http_client import make_session


class SessionCortexApi(Api):
    def __init__(self, url, api_key, **kwargs):
        super().__init__(url, api_key, **kwargs)
        self._session = make_session()

    def _headers(self, *, json: bool = False) -> dict:
        h = {"Authorization": "Bearer %s" % self._Api__api_key}
        if json:
            h["Content-Type"] = "application/json"
        return h

    def _url(self, endpoint: str) -> str:
        return "%s%s" % (self._Api__base_url, endpoint)

    def _execute(self, method: str, endpoint: str, **request_kwargs):
        try:
            response = self._session.request(
                method,
                self._url(endpoint),
                proxies=self._Api__proxies,
                verify=self._Api__verify_cert,
                **request_kwargs,
            )
            response.raise_for_status()
            return response
        except Exception as exc:
            self._Api__recover(exc)

    def do_get(self, endpoint, params=None):
        return self._execute("GET", endpoint, headers=self._headers(), params=params or {})

    def do_file_post(self, endpoint, data, **kwargs):
        return self._execute(
            "POST", endpoint, headers=self._headers(), data=data, **kwargs
        )

    def do_post(self, endpoint, data, params=None, **kwargs):
        return self._execute(
            "POST", endpoint,
            headers=self._headers(json=True),
            json=data, params=params or {}, **kwargs,
        )

    def do_patch(self, endpoint, data, params=None):
        return self._execute(
            "PATCH", endpoint,
            headers=self._headers(json=True),
            json=data, params=params or {},
        )

    def do_delete(self, endpoint):
        response = self._execute("DELETE", endpoint, headers=self._headers())
        return True if response is not None else False
