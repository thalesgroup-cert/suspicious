"""
GET /api/feeder/health/

Server-side proxy to the email_feeder container's /health endpoint
(exposed on its in-cluster port 9091). The browser never talks to the
feeder directly: only the Django backend (on the same Docker network)
can reach it. We re-expose a sanitised payload to Admin/CERT users so
the UI can render a live runtime-status badge.

Payload shape:
{
  "online": bool,                       # could we reach /health at all
  "last_successful_poll": int | None,   # unix epoch (None when never polled)
  "emails_processed_total": int,
  "errors_total": int,
  "stale_seconds": int,                 # how long since the last poll
  "stale": bool,                        # stale_seconds > STALE_THRESHOLD_S
  "checked_at": int,                    # unix epoch of this check
  "error": str | None,                  # populated when online=False
}
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.settings import IsAdminOrCERT

logger = logging.getLogger(__name__)


# Internal Docker DNS — both containers are on suspicious_network and
# the feeder healthcheck binds 9091.
_FEEDER_HEALTH_URL = "http://email_feeder:9091/health"

# Hard ceiling so a hanging feeder cannot wedge the Django thread.
_FEEDER_HEALTH_TIMEOUT_S = 3.0

# Anything older than this is considered "stale" — the feeder may be
# alive (responding to /health) but is no longer polling mailboxes.
# Polling cadence is the IMAP-side `polling_interval` (default 60 s),
# so 5 min is comfortably above legitimate gaps.
_FEEDER_STALE_THRESHOLD_S = 5 * 60


class FeederHealthView(APIView):
    """Live status of the email_feeder service.

    Returns 200 in all reachability scenarios (online or offline); the
    `online` flag tells the UI how to render. We do *not* return 5xx
    when the feeder is down because that would surface as a generic
    error toast — the badge needs the full payload.
    """

    permission_classes = [IsAuthenticated, IsAdminOrCERT]

    def get(self, request, *args, **kwargs) -> Response:
        now_ts = int(time.time())
        payload: dict[str, Any] = {
            "online": False,
            "last_successful_poll": None,
            "emails_processed_total": 0,
            "errors_total": 0,
            "stale_seconds": 0,
            "stale": True,
            "checked_at": now_ts,
            "error": None,
        }

        try:
            resp = requests.get(_FEEDER_HEALTH_URL, timeout=_FEEDER_HEALTH_TIMEOUT_S)
        except requests.RequestException as exc:
            logger.info("Feeder /health unreachable: %s", exc)
            payload["error"] = f"unreachable: {exc.__class__.__name__}"
            return Response(payload)

        if resp.status_code != 200:
            payload["error"] = f"http_{resp.status_code}"
            return Response(payload)

        try:
            data = resp.json()
        except ValueError:
            payload["error"] = "invalid_json"
            return Response(payload)

        last_poll_raw = data.get("last_successful_poll", 0)
        try:
            last_poll = float(last_poll_raw)
        except (TypeError, ValueError):
            last_poll = 0.0

        # last_successful_poll == 0 means the feeder has not polled
        # anything yet since the container started — keep it as null
        # in the API so the UI doesn't print "1970-01-01".
        last_poll_int = int(last_poll) if last_poll > 0 else None
        stale_seconds = max(0, now_ts - int(last_poll)) if last_poll > 0 else 0

        # Our own staleness view: never polled, or last poll older than
        # the threshold.
        poll_is_stale = (
            last_poll_int is None or stale_seconds > _FEEDER_STALE_THRESHOLD_S
        )

        # Feeder /health reports a `status` (ok|degraded) plus per-subsystem
        # checks (IMAP, MinIO). Older feeder builds omit `status`, so derive
        # it from our staleness view rather than blindly defaulting to "ok" —
        # otherwise the badge reads "ok" while `stale` is True.
        feeder_status = data.get("status") or ("degraded" if poll_is_stale else "ok")
        feeder_checks = data.get("checks") or {}

        payload.update({
            "online": True,
            "last_successful_poll": last_poll_int,
            "emails_processed_total": int(data.get("emails_processed_total", 0)),
            "errors_total": int(data.get("errors_total", 0)),
            "stale_seconds": stale_seconds,
            # `stale` becomes True if either the proxy thinks the last
            # poll is too old OR the feeder itself reports degraded —
            # the latter covers the case where IMAP is responding but
            # MinIO uploads have been failing.
            "stale": poll_is_stale or feeder_status == "degraded",
            "feeder_status": feeder_status,
            "checks": feeder_checks,
            "error": None,
        })
        return Response(payload)
