import logging
import requests
from django.db import transaction
from cortex4py.exceptions import CortexException
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
def _fetch_all_analyzers(api):
    """Fetch every analyzer enabled for the org, with retry and circuit
    breaker.

    Not api.analyzers.find_all(): cortex4py implements that as
    POST /api/analyzer/_search, an endpoint this Cortex version (4.1.0, the
    one this project targets) no longer serves — it 404s, so the sync task
    silently never updated a single Analyzer row. GET /api/analyzer (what
    get_by_type/the Cortex UI itself use) is the one that actually works.
    """
    with _cortex_breaker.calling():
        data = api.do_get("analyzer", params={"range": "all"}).json()
        return [CortexAnalyzer(item) for item in data]


def sync_cortex_analyzers(config_path: str = CONFIG_PATH) -> None:
    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    # CortexConfig.url is a pydantic HttpUrl, which renders a bare host with
    # a trailing slash (e.g. "http://cortex:9001/"). cortex4py's Api always
    # appends "/api/" to the url it's given, so an untrimmed trailing slash
    # here silently produced "http://cortex:9001//api/..." — a 404 on every
    # call. Every other Cortex client in this codebase reads the same
    # integrations.cortex.url from settings.json directly (no trailing
    # slash) and never hit this.
    api = SessionCortexApi(str(cfg.cortex.url).rstrip("/"), cfg.cortex.api_key)

    try:
        remote_analyzers = _fetch_all_analyzers(api)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open — sync_cortex_analyzers skipped: %s", exc)
        return
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        return
    except requests.RequestException as exc:
        log_analyzers.error("Network error syncing Cortex analyzers: %s", exc)
        return

    if not remote_analyzers:
        return

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={"analyzer_cortex_id": analyzer.id, "is_active": True},
                create_defaults={
                    "analyzer_cortex_id": analyzer.id,
                    "is_active": True,
                    "tier": tier_for(analyzer.name),
                },
            )
            remote_names.append(analyzer.name)
        Analyzer.objects.exclude(name__in=remote_names).update(is_active=False)

    _warn_on_unresolved_configured_analyzers(remote_names)


def _warn_on_unresolved_configured_analyzers(remote_names: list[str]) -> None:
    """integrations.cortex.analyzers.{header,ai,sandbox,yara,file_info} are
    plain name strings that cortex_and_job_management's dispatch resolves via
    api.analyzers.get_by_name() at *dispatch* time — a miss there is just a
    fetch_mail_logger.warning() next to hundreds of routine ones, easy to
    never notice (this is exactly how "header": "MailHeader_4_0" sat wrong
    for who knows how long: the repo's real header analyzer is
    Mail_Header_Analyzer_1_0, so mail_header jobs for it silently never
    fired). Cross-check against the analyzer list this same task just
    fetched and log loudly — same 404/breaker/network exceptions above still
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
        if name and name not in remote_set:
            log_analyzers.error(
                "integrations.cortex.analyzers.%s = %r does not match any analyzer "
                "currently enabled in Cortex — dispatch for this role will silently "
                "find nothing every time. Check the analyzer's real registered name "
                "(Cortex organization analyzer list) against settings.json.",
                role, name,
            )
