import contextlib
import logging
import requests
from django.db import transaction
from cortex4py.exceptions import AuthenticationError, CortexException
from cortex4py.models import Analyzer as CortexAnalyzer
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi
from .utils import load_config
from .models import CronConfig
from cortex_job.models import Analyzer
from cortex_job.migrations._tier_seed import tier_for
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

    try:
        remote_analyzers = _fetch_all_analyzers(api, guarded=not strict)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open, sync_cortex_analyzers skipped: %s", exc)
        if strict:
            raise
        return
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        if strict:
            # A revoked or wrong API key (401/403) waits for an operator, not a retry.
            if isinstance(exc, AuthenticationError):
                exc.retryable = False
            raise
        return
    except requests.RequestException as exc:
        log_analyzers.error("Network error syncing Cortex analyzers: %s", exc)
        if strict:
            raise
        return

    if not remote_analyzers:
        return 0

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            owner = Analyzer.objects.filter(name=analyzer.name).values_list("source", flat=True).first()
            if owner is not None and owner != "cortex":
                # Analyzer.name is unique across sources: another connector owns this one.
                log_analyzers.error(
                    "Cortex offers analyzer %r but it belongs to %r; skipped.", analyzer.name, owner)
                continue
            Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={"analyzer_cortex_id": analyzer.id, "is_active": True, "source": "cortex"},
                create_defaults={
                    "analyzer_cortex_id": analyzer.id,
                    "is_active": True,
                    "source": "cortex",
                    "tier": tier_for(analyzer.name),
                },
            )
            remote_names.append(analyzer.name)
        # The AI vote's row (ai_model connector) is no Cortex analyzer: leave it active.
        from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
        Analyzer.objects.filter(source="cortex").exclude(name__in=[*remote_names, ai_analyzer_name()]).update(is_active=False)

    _warn_on_unresolved_configured_analyzers(remote_names)
    return len(remote_names)


def _warn_on_unresolved_configured_analyzers(remote_names: list[str]) -> None:
    """integrations.cortex.analyzers.{header,sandbox,yara,file_info} are
    plain name strings that cortex_and_job_management's dispatch resolves via
    api.analyzers.get_by_name() at *dispatch* time: a miss there is just a
    fetch_mail_logger.warning() next to hundreds of routine ones, easy to
    never notice (this is exactly how "header": "MailHeader_4_0" sat wrong
    for who knows how long: the repo's real header analyzer is
    Mail_Header_Analyzer_1_0, so mail_header jobs for it silently never
    fired). Cross-check against the analyzer list this same task just
    fetched and log loudly; same 404/breaker/network exceptions above still
    apply, so this only ever runs when the fetch itself succeeded, i.e. this
    IS the authoritative, current set of what Cortex has enabled.
    """
    try:
        from settings.config import get_section
        configured = get_section("integrations.cortex").get("analyzers", {}) or {}
    except Exception as exc:
        log_analyzers.error("Could not load integrations.cortex.analyzers to validate: %s", exc)
        return

    remote_set = set(remote_names)
    for role, name in configured.items():
        # ai names the AI vote's Analyzer row (ai_model connector), not a Cortex analyzer.
        if role != "ai" and name and name not in remote_set:
            log_analyzers.error(
                "integrations.cortex.analyzers.%s = %r does not match any analyzer "
                "currently enabled in Cortex; dispatch for this role will silently "
                "find nothing every time. Check the analyzer's real registered name "
                "(Cortex organization analyzer list) against settings.json.",
                role, name,
            )
