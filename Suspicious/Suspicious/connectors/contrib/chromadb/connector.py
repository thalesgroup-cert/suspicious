"""ChromaDB connector — nightly cleanup of expired similarity-collection
items. Wraps every call in a background-thread timeout because chromadb's
own HttpClient hardcodes httpx.Client(timeout=None, ...) with no override
(confirmed against the installed chromadb 1.5.8 source) — without this, a
hung ChromaDB server blocks the calling task until Celery's global
task_soft_time_limit fires, ~9 minutes later, and the resulting error gets
swallowed instead of retried."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta
from typing import Callable, TypeVar

from connectors.base import Connector, ConnectorManifest, HealthStatus, Schedule

logger = logging.getLogger("connectors.contrib.chromadb")

_DEFAULT_TIMEOUT_SECONDS = 30
_DEFAULT_THRESHOLD_DAYS = 15
_DEFAULT_COLLECTION_NAME = "suspicious"

T = TypeVar("T")


def _run_with_timeout(fn: Callable[[], T], timeout: float) -> T:
    """Run fn() in a background thread, bounding its execution time.

    The abandoned thread isn't force-killed on timeout; it lingers until the
    underlying TCP connection eventually gives up on its own. Acceptable:
    Celery workers recycle periodically, and the alternative (blocking
    forever) is strictly worse.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fn)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        raise TimeoutError(f"ChromaDB call did not complete within {timeout}s") from None
    finally:
        pool.shutdown(wait=False)


class ChromaDBConnector(Connector):
    manifest = ConnectorManifest(
        name="chromadb",
        version="1.0.0",
        author="Thales CERT",
        category="Maintenance",
        description=(
            "Nightly cleanup of expired items in the suspicious-mail "
            "similarity collection."
        ),
        config_schema=(),
        events=(),
        schedules=(Schedule("cleanup", 86400),),
        enabled_by_default=True,
    )

    def _timeout(self) -> float:
        return float(self.config.get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS))

    def health_check(self) -> HealthStatus:
        from common.clients import get_chroma_client
        try:
            client = _run_with_timeout(get_chroma_client, self._timeout())
            _run_with_timeout(client.heartbeat, self._timeout())
            return HealthStatus(ok=True, detail="reachable")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def sync(self) -> None:
        from common.clients import get_chroma_client

        collection_name = self.config.get("collection_name", _DEFAULT_COLLECTION_NAME)
        threshold_days = int(self.config.get("threshold_days", _DEFAULT_THRESHOLD_DAYS))
        cutoff = datetime.now() - timedelta(days=threshold_days)
        timeout = self._timeout()

        def _do_cleanup() -> int:
            client = get_chroma_client()
            collection = client.get_collection(name=collection_name)
            items = collection.get()
            expired_ids = [
                items["ids"][i]
                for i, meta in enumerate(items.get("metadatas", []))
                if meta
                and "detection_date" in meta
                and datetime.strptime(meta["detection_date"], "%Y-%m-%d %H:%M:%S.%f") < cutoff
            ]
            if expired_ids:
                collection.delete(ids=expired_ids)
            return len(expired_ids)

        deleted = _run_with_timeout(_do_cleanup, timeout)
        logger.info("Deleted %d expired item(s) from collection %r", deleted, collection_name)
