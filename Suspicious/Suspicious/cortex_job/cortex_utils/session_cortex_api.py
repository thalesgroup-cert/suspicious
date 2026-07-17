"""cortex4py Api subclass that routes do_* through a shared Session
with TimeoutHTTPAdapter — needed because vanilla Api uses bare
requests.get/post with no socket timeout.
"""
from __future__ import annotations

import requests
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
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code >= 500:
                # Let common.http_client.RETRY see and retry the original
                # HTTPError for 5xx — cortex4py's __recover() below rewraps
                # it into InvalidInputError, which isn't a requests.HTTPError
                # subclass and would defeat RETRY's 5xx retry predicate.
                raise
            self._Api__recover(exc)
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
        return response is not None
