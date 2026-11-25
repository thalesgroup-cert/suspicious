import contextlib
import logging
import requests
from cortex4py.exceptions import CortexException
from cortex4py.models import Analyzer as CortexAnalyzer
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi
from .utils import load_config
from .models import CronConfig
import pybreaker
from common.http_client import get_breaker, RETRY

logger = logging.getLogger("tasp.cron.sync_cortex")
log_analyzers = logging.getLogger("tasp.cron.fetch_analyzer")
import os as _os_cfg
CONFIG_PATH = _os_cfg.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")

_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_all_analyzers(api, guarded: bool = True):
    """Fetch every analyzer enabled for the org, with retry and circuit
    breaker.

    Not api.analyzers.find_all(): cortex4py implements that as
    POST /api/analyzer/_search, an endpoint this Cortex version (4.1.0, the
    one this project targets) no longer serves: it 404s, so the sync task
    silently never updated a single Analyzer row. GET /api/analyzer (what
    get_by_type/the Cortex UI itself use) is the one that actually works.
    """
    # guarded=False when the caller already runs under the "cortex" breaker (the connector
    # sync via run_sync_now): the same breaker counted twice would trip early.
    with _cortex_breaker.calling() if guarded else contextlib.nullcontext():
        data = api.do_get("analyzer", params={"range": "all"}).json()
        return [CortexAnalyzer(item) for item in data]


def sync_cortex_analyzers(config_path: str = CONFIG_PATH, strict: bool = False) -> int | None:
    """Mirror the Cortex catalogue into ``Analyzer``. Returns the number of analyzers
    synced. A fetch failure is logged and swallowed, unless ``strict`` (the connector
    sync), which re-raises it so the delivery ledger records a failure."""
    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    # CortexConfig.url is a pydantic HttpUrl, which renders a bare host with
    # a trailing slash (e.g. "http://cortex:9001/"). cortex4py's Api always
    # appends "/api/" to the url it's given, so an untrimmed trailing slash
    # here silently produced "http://cortex:9001//api/...": a 404 on every
    # call. Every other Cortex client in this codebase reads the same
    # integrations.cortex.url from settings.json directly (no trailing
    # slash) and never hit this.
    api = SessionCortexApi(str(cfg.cortex.url).rstrip("/"), cfg.cortex.api_key)

    from connectors.contrib.cortex.connector import CortexConnector
    from connectors.engines import sync_connector_catalog

    connector = CortexConnector({"url": str(cfg.cortex.url).rstrip("/"), "api_key": cfg.cortex.api_key})
    connector._client = api
    connector.guarded = not strict
    try:
        return sync_connector_catalog("cortex", connector)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open, sync_cortex_analyzers skipped: %s", exc)
        if strict:
            raise
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        if strict:
            raise
    except requests.RequestException as exc:
        log_analyzers.error("Network error syncing Cortex analyzers: %s", exc)
        if strict:
            raise
