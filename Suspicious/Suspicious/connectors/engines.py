"""Analysis engines: the only code the pipeline calls to start analyzer jobs.

Every enabled connector whose manifest ``provides`` "analysis" (Cortex first)
offers analyzers through ``catalog``; ``select_analyzers`` is the one policy
that picks among them, and ``dispatch`` alone writes the AnalyzerReport and
CaseAnalyzerJob rows, exactly as ``CortexJob.run_analyzer`` did.
"""
from __future__ import annotations

import dataclasses
import logging

from django.db import transaction
from django.utils import timezone

from connectors.base import (
    DATA_TYPE_MAIL_ARCHIVE,
    FETCH_GONE,
    FETCH_RESULT,
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    FetchResult,
    WebhookNotConfigured,
)
from connectors.registry import registry

logger = logging.getLogger(__name__)

ID_MAX_LENGTH = 50  # Analyzer.analyzer_cortex_id and CaseAnalyzerJob.cortex_job_id

# Data types whose analyzers are the configured roles, looked up by name.
ROLE_TYPES = {
    "file": ("yara", "file_info", "sandbox"),
    "mail_body": ("yara",),
    "mail_header": ("header",),
    DATA_TYPE_MAIL_ARCHIVE: ("ai",),
}
EML_EXCLUDED_ROLES = ("ai", "yara", "sandbox", "header")
GENERIC_EXCLUDED_ROLES = ("yara", "sandbox", "header")


def _role_names(roles: dict, wanted) -> set[str]:
    # Only set names: an absent or empty role must never put None or {} into the set.
    return {roles[r] for r in wanted if roles.get(r)}


def enabled_engines() -> list[str]:
    from connectors.delivery import get_state  # lazy: delivery imports the registry too

    return sorted(n for n in registry.providers(PROVIDER_KIND_ANALYSIS) if get_state(n).enabled)


def select_analyzers(data_type: str, value, offered: list[CatalogEntry], roles: dict) -> list[CatalogEntry]:
    """The analyzer selection policy, from launch_cortex_jobs, get_file_analyzers and
    get_analyzers_by_type. Raises TypeError for a file without ``file_path.name``, as they did."""
    if data_type in ROLE_TYPES:
        keep = _role_names(roles, ROLE_TYPES[data_type])
        if data_type == "file":
            if not hasattr(value, "file_path") or not hasattr(value.file_path, "name"):
                raise TypeError("file must have 'file_path.name' attribute")
            if value.file_path.name.endswith(".eml"):
                keep -= _role_names(roles, EML_EXCLUDED_ROLES)
        # mail_archive is no observable: only an analyzer that declares it may run on it.
        return [entry for entry in offered if entry.name in keep
                and (data_type != DATA_TYPE_MAIL_ARCHIVE or data_type in entry.data_types)]
    excluded = _role_names(roles, GENERIC_EXCLUDED_ROLES)
    return [entry for entry in offered if entry.name not in excluded]


def ledger_ids(connector: str, ext_job_id: str, ext_analyzer_id: str) -> tuple[str, str]:
    """(CaseAnalyzerJob.cortex_job_id, Analyzer.analyzer_cortex_id): raw for Cortex,
    namespaced for any other engine. ValueError when either exceeds the column."""
    if connector == "cortex":
        ids = (ext_job_id, ext_analyzer_id)
    else:
        ids = (f"{connector}-{ext_job_id}", f"{connector}:{ext_analyzer_id}")
    if max(len(i) for i in ids) > ID_MAX_LENGTH:
        raise ValueError(f"{connector} id over {ID_MAX_LENGTH} characters")
    return ids


def dispatch(value, data_type: str, case) -> list[str]:
    """Start the selected analyzers of every enabled engine on ``value``; returns the
    ledger job ids. One engine or analyzer failing never stops the others, and dispatch
    never raises (callers rely on it, as on launch_cortex_jobs) except TypeError for no case."""
    if case is None:
        raise TypeError("dispatch requires a non-None case")
    job_ids: list[str] = []
    try:
        _dispatch(value, data_type, case, job_ids)
    except Exception:  # noqa: BLE001
        logger.exception("Dispatch of %s failed (case=%s)", data_type, case.id)
    return job_ids


def _roles() -> dict:
    """integrations.cortex.analyzers; empty (logged) when the config cannot be read. The ``ai``
    role always has a name: ai_analyzer_name() supplies its default."""
    from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
    from settings.config import get_section

    try:
        roles = dict(get_section("integrations.cortex").get("analyzers") or {})
    except Exception as exc:  # noqa: BLE001
        logger.error("Could not load cortex analyzer roles: %s", exc)
        roles = {}
    roles["ai"] = ai_analyzer_name()
    return roles


def _dispatch(value, data_type, case, job_ids) -> None:
    names = enabled_engines()
    if not names:
        logger.warning("no analysis engine enabled; %s on case %s not analysed", data_type, case.id)
        return

    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob

    try:
        data_value = CortexJob.get_data_value(value, data_type)
    except Exception as exc:  # noqa: BLE001
        logger.error("Error extracting data value for %s: %s", data_type, exc)
        return
    if not data_value or (isinstance(data_value, str) and not data_value.strip()):
        logger.debug("Skip %s dispatch: empty data value", data_type)
        return

    roles = _roles()
    for name in names:
        try:
            _dispatch_engine(name, value, data_type, data_value, case, roles, job_ids)
        except Exception as exc:  # noqa: BLE001: one engine must not stop the others
            logger.error("Engine %s failed to dispatch %s: %s", name, data_type, type(exc).__name__)


def _dispatch_engine(name, value, data_type, data_value, case, roles, job_ids) -> None:
    from cortex_job.models import Analyzer

    connector = registry.instantiate(name)
    if data_type in ROLE_TYPES:
        offered = [
            entry
            for role in ROLE_TYPES[data_type] if roles.get(role)
            for entry in connector.catalog(name=roles[role])
        ]
    else:
        offered = connector.catalog(data_type=data_type)

    for entry in select_analyzers(data_type, value, offered, roles):
        owners = Analyzer.objects.filter(name=entry.name).exclude(source=name)
        if name != "cortex":  # rows _analyzer_row adopts are no conflict
            owners = [o for o in owners.only("analyzer_cortex_id") if not _adoptable(entry, o.analyzer_cortex_id)]
        if owners:
            logger.error("Engine %s offers analyzer %r, owned by another source: skipped", name, entry.name)
            continue
        try:
            job_id = _start(connector, name, entry, value, data_type, data_value, case)
        except Exception as exc:  # noqa: BLE001: one analyzer must not stop the others
            logger.error("Error running analyzer %s on %s: %s", entry.name, name, type(exc).__name__)
            continue
        if job_id:
            job_ids.append(job_id)


PROVIDER_ANALYZER_PREFIX = "provider:"  # Analyzer rows created by the old provider path


def _adoptable(entry, analyzer_cortex_id: str) -> bool:
    """Whether a non-Cortex engine takes over an existing row of the entry's name from another
    source: a row of the old provider path, or any row when the entry runs on mail_archive (no
    observable: a row of that name can only be a wrong owner, such as a Cortex mirror)."""
    return (analyzer_cortex_id.startswith(PROVIDER_ANALYZER_PREFIX)
            or DATA_TYPE_MAIL_ARCHIVE in entry.data_types)


def _analyzer_row(name, entry, analyzer_id):
    """The engine's Analyzer row. Cortex: by its raw id, as run_analyzer did. Any other engine:
    by name first, adopting a row of the old provider path or, for a mail_archive entry, any row of
    the name (its id kept); created only when none has the name."""
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
    from cortex_job.models import Analyzer

    if name != "cortex":
        row = Analyzer.objects.filter(name=entry.name).first()
        if row is not None:
            if row.source != name and _adoptable(entry, row.analyzer_cortex_id):
                row.source = name
                row.save(update_fields=["source"])
            return row
    return CortexJob.get_analyzer_db(dataclasses.replace(entry, id=analyzer_id), source=name)


def _failed_start(name, case, analyzer_name, reason) -> None:
    from connectors.models import ConnectorDelivery

    ConnectorDelivery.objects.create(
        connector=name, event="start", case_id=case.id,
        status=ConnectorDelivery.STATUS_FAILED, error=f"{analyzer_name}: {reason}",
    )


def _start(connector, name, entry, value, data_type, data_value, case) -> str | None:
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
    from cortex_job.models import AnalyzerReport, CaseAnalyzerJob

    try:  # the analyzer id is known now: refuse it before an external job exists
        analyzer_id = ledger_ids(name, "", str(entry.id))[1]
    except ValueError:
        logger.error("Engine %s analyzer %r: id too long, not started", name, entry.name)
        _failed_start(name, case, entry.name, "id too long")
        return None

    try:
        started = connector.start(entry, data_type, data_value)
    except Exception as exc:  # noqa: BLE001: the class name only, never a URL or secret
        logger.warning("Engine %s failed to start %s on %s: %s", name, entry.name, data_type, type(exc).__name__)
        _failed_start(name, case, entry.name, type(exc).__name__)
        return None
    if not started:  # a refusal is routine (the engine logs it): no ledger row
        logger.debug("Engine %s refused %s on %s", name, entry.name, data_type)
        return None

    try:
        job_id = ledger_ids(name, str(started.job_id), "")[0]
    except ValueError:
        logger.error("Engine %s job id for %r too long: started job not recorded", name, entry.name)
        _failed_start(name, case, entry.name, "job id too long")
        return None

    if started.deferred:
        _start_deferred(connector, name, entry, analyzer_id, job_id, case)
        return job_id

    with transaction.atomic():
        analyzer_db = _analyzer_row(name, entry, analyzer_id)
        analyzer_report = AnalyzerReport(
            cortex_job_id=job_id,
            type=data_type,
            analyzer=analyzer_db,
            status="InProgress",
            level="info",
            confidence=0,
            score=0,
            report_summary={"ongoing": "analysis"},
            report_full={"ongoing": "analysis"},
            report_taxonomy={"ongoing": "analysis"},
        )
        CortexJob.set_analyzer_report_data(analyzer_report, value, data_type)
        finished = started.finished
        status = CaseAnalyzerJob.STATUS_INPROGRESS
        if finished:  # an instant engine: store the result now, the row never waits for refresh
            if store_result(analyzer_report, finished):
                status = analyzer_report.status
            else:  # left as the placeholder: refresh or the stale timeout handles the row
                logger.warning("Engine %s finished start for %s not stored (state %r, data type %r, expected %r)",
                               name, entry.name, finished.state, finished.data_type, data_type)
                finished = None
        CaseAnalyzerJob.objects.create(
            case=case,
            cortex_job_id=job_id,
            analyzer=analyzer_db,
            analyzer_report=analyzer_report,
            status=status,
            completed_at=None if status in CaseAnalyzerJob.PENDING_STATUSES else timezone.now(),
        )
    if finished and finished.status == "Success":
        _score(analyzer_report)
    return job_id


def _start_deferred(connector, name, entry, analyzer_id, job_id, case) -> None:
    """A deferred job: a pending row with no report, closed by run_engine_job in a worker."""
    from connectors.tasks import run_engine_job
    from cortex_job.models import CaseAnalyzerJob

    with transaction.atomic():
        analyzer_db = _analyzer_row(name, entry, analyzer_id)
        row = CaseAnalyzerJob.objects.create(
            case=case, cortex_job_id=job_id, analyzer=analyzer_db,
            analyzer_report=None, status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
        try:
            with transaction.atomic():  # a savepoint: a failing hook never undoes the row
                connector.on_started(case, entry.name)
        except Exception as exc:  # noqa: BLE001: the class name only, a message may carry data
            logger.error("Engine %s on_started for %s failed: %s", name, entry.name, type(exc).__name__)
        transaction.on_commit(lambda: run_engine_job.delay(row.id))


# ── refresh: reconcile reads job results through the engine ────────────────

DEFAULT_STALE_JOB_TIMEOUT_SECONDS = 7200
_PENDING_REPORT = ("Waiting", "InProgress")


def stale_timeout(name: str) -> int:
    """The engine's ``stale_job_timeout_seconds``; 7200 when absent, unreadable or unregistered."""
    if name not in registry.names():
        return DEFAULT_STALE_JOB_TIMEOUT_SECONDS
    from settings.config import get_section

    try:
        value = get_section(f"integrations.{name}").get("stale_job_timeout_seconds")
        return int(value) if value not in (None, "") else DEFAULT_STALE_JOB_TIMEOUT_SECONDS
    except Exception as exc:  # noqa: BLE001
        logger.warning("Stale timeout of %s unreadable (%s): using the default", name, type(exc).__name__)
        return DEFAULT_STALE_JOB_TIMEOUT_SECONDS


def apply_result(report_instance, result: FetchResult) -> list[str]:
    """Set the result's status, and on Success its summary, taxonomies and full, on the
    report; returns the changed field names (not saved). CortexJobManager.update_report_instance."""
    updated_fields = []
    if report_instance.status != result.status:
        report_instance.status = result.status
        updated_fields.append("status")
    if result.status == "Success":
        summary = result.summary
        if summary and summary != report_instance.report_summary:
            report_instance.report_summary = summary
            updated_fields.append("report_summary")
        taxonomies = summary.get("taxonomies") if summary else None
        if taxonomies and taxonomies != report_instance.report_taxonomy:
            report_instance.report_taxonomy = taxonomies
            updated_fields.append("report_taxonomy")
        if result.full and result.full != report_instance.report_full:
            report_instance.report_full = result.full
            updated_fields.append("report_full")
    return updated_fields


def store_result(report, result: FetchResult) -> bool:
    """Write a fetched or finished-at-start result onto its report and save it. False, with
    nothing written, when the result's data type is set and differs from the report's
    (mail_body matches file). A Success with no body keeps the status; a Failure carries
    no body (Cortex sends errorMessage) and is written, so only Success needs one."""
    if result.state != FETCH_RESULT:
        return False
    data_type = report.type
    if result.data_type and result.data_type != data_type and not (
        data_type == "mail_body" and result.data_type == "file"
    ):
        return False
    if result.summary is not None or result.full is not None or result.status != "Success":
        fields = apply_result(report, result)
        if fields:
            report.save(update_fields=fields)
    return True


def _score(report_instance) -> None:
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    try:
        CortexAnalyzerReports.create_and_save_report(
            report_instance, CortexJobManager._artifact_value(report_instance), None
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error scoring report %s: %s", report_instance.cortex_job_id, exc, exc_info=True)


def update_report(report_instance, fetched: FetchResult, stale_timeout: int) -> str:
    """Write one fetched job onto its report, as get_cortex_jobs_results did; returns the status.
    gone: Deleted. unknown: nothing. result of the report's data type: the status, and the body
    when there is one; Success is scored. A report still pending past ``stale_timeout`` fails."""
    from cortex_job.models import CaseAnalyzerJob

    job_id = report_instance.cortex_job_id
    if fetched.state == FETCH_GONE:
        if report_instance.status != "Deleted":
            report_instance.status = "Deleted"
            report_instance.save(update_fields=["status"])
        return report_instance.status

    if fetched.state == FETCH_RESULT:
        try:
            stored = store_result(report_instance, fetched)
        except Exception as exc:  # noqa: BLE001
            logger.error("Error updating report %s: %s", job_id, exc, exc_info=True)
            stored = True
        if stored and fetched.status == "Success":
            _score(report_instance)

    if report_instance.status in _PENDING_REPORT:
        submitted_at = (
            CaseAnalyzerJob.objects
            .filter(cortex_job_id=job_id)
            .order_by("created_at")
            .values_list("created_at", flat=True)
            .first()
        ) or report_instance.creation_date
        if submitted_at is not None:
            age = (timezone.now() - submitted_at).total_seconds()
            if age > stale_timeout:
                logger.warning(
                    "Auto-failing stale %s report cortex_job_id=%s after %.0fs",
                    report_instance.status, job_id, age,
                )
                report_instance.status = "Failure"
                report_instance.save(update_fields=["status"])
    return report_instance.status


def _external_job_id(name: str, ledger_job_id: str) -> str:
    """Inverse of ledger_ids for the job id."""
    prefix = f"{name}-"
    if name != "cortex" and ledger_job_id.startswith(prefix):
        return ledger_job_id[len(prefix):]
    return ledger_job_id


def refresh(caj, cache: dict | None = None) -> None:
    """Sync one CaseAnalyzerJob and its report from the engine that owns its analyzer.
    ``cache`` (ledger job id -> FetchResult) makes rows sharing a job fetch it once.
    A disabled engine is still fetched: its started jobs must finish."""
    report = caj.analyzer_report
    if report is None:  # a deferred job: run_engine_job closes it
        return
    name = caj.analyzer.source
    if name not in registry.names():
        logger.warning("No engine %r registered for job %s: not refreshed", name, caj.cortex_job_id)
        return
    if name not in registry.providers(PROVIDER_KIND_ANALYSIS):
        logger.debug("Row %s: source %r provides no analysis: not refreshed", caj.cortex_job_id, name)
        return
    cache = {} if cache is None else cache
    try:
        fetched = cache.get(caj.cortex_job_id)
        if fetched is None:
            engine = registry.instantiate(name)
            fetched = cache[caj.cortex_job_id] = engine.fetch(_external_job_id(name, caj.cortex_job_id))
        close_row(caj, update_report(report, fetched, stale_timeout(name)))
    except Exception as exc:  # noqa: BLE001: one bad row must not stall the reconcile pass
        logger.error("Refresh of job %s failed: %s", caj.cortex_job_id, type(exc).__name__)


def close_row(caj, new_status) -> None:
    """The row mirrors its report; completed_at is set when it leaves the pending states."""
    from cortex_job.models import CaseAnalyzerJob

    if new_status and new_status != caj.status:
        caj.status = new_status
        if new_status not in CaseAnalyzerJob.PENDING_STATUSES:
            caj.completed_at = timezone.now()
        caj.save(update_fields=["status", "completed_at"])


# ── webhook: an engine announces finished jobs ─────────────────────────────

WEBHOOK_DEDUP_TTL = 3600


def _pending_case_ids(name: str, ext_job_id: str) -> list[int]:
    from cortex_job.models import CaseAnalyzerJob

    try:
        ledger_id = ledger_ids(name, ext_job_id, "")[0]
    except ValueError:  # too long for the ledger: no row can carry it
        return []
    return list(
        CaseAnalyzerJob.objects
        .filter(cortex_job_id=ledger_id, status__in=CaseAnalyzerJob.PENDING_STATUSES)
        .values_list("case_id", flat=True)
        .distinct()
    )


def handle_webhook(connector_name: str, headers, payload) -> tuple[int, dict]:
    """Authenticate through the engine, drop duplicates, and queue reconcile_case for the cases
    owning the announced jobs. Returns (http status, body). A disabled engine is still accepted:
    its started jobs must finish."""
    import time

    from django.core.cache import cache

    if connector_name not in registry.names():
        return 404, {"detail": "Not found."}
    if registry.get(connector_name).manifest.provides != PROVIDER_KIND_ANALYSIS:
        return 404, {"detail": "Not found."}
    try:
        try:
            engine = registry.instantiate(connector_name)
        except Exception as exc:  # noqa: BLE001: runtime config unreadable; log the class only
            logger.error("%s webhook: config unreadable (%s), using an empty config",
                         connector_name, type(exc).__name__)
            engine = registry.get(connector_name)({})  # so the settings secret is the fallback
        announced = engine.webhook(headers, payload)
    except NotImplementedError:
        return 404, {"detail": "Not found."}
    except WebhookNotConfigured:
        logger.error("%s webhook secret not configured, webhook rejected", connector_name)
        return 503, {"detail": "Webhook not configured."}
    if announced is None:
        logger.warning("%s webhook: invalid or missing credentials", connector_name)
        return 401, {"detail": "Unauthorized."}

    cache.set(f"{connector_name}_last_webhook_at", time.time(), timeout=None)
    if not announced:  # also a whitespace-only jobId: deliberately 400, no longer a 202
        return 400, {"detail": "jobId is required."}

    fresh = [j for j in announced if cache.add(f"{connector_name}_job_processed:{j}", 1, timeout=WEBHOOK_DEDUP_TTL)]
    if not fresh:
        logger.info("%s webhook duplicate jobId=%s; skipping", connector_name, ",".join(announced))
        return 200, {"detail": "Already processed."}

    case_ids = sorted({c for j in fresh for c in _pending_case_ids(connector_name, j)})
    if not case_ids:
        logger.info("%s webhook: no pending job for jobId=%s; cron fallback covers it",
                    connector_name, ",".join(fresh))
        return 202, {"detail": "No pending case found."}

    from tasp.tasks import reconcile_case
    for case_id in case_ids:
        reconcile_case.delay(case_id)
        logger.info("Queued %s update for case=%s jobId=%s", connector_name, case_id, ",".join(fresh))
    return 202, {"detail": f"Queued update for {len(case_ids)} case(s)."}


# ── catalogue sync ─────────────────────────────────────────────────────────

log_sync = logging.getLogger("tasp.cron.fetch_analyzer")


def sync_catalog(connector_name: str) -> int:
    """Mirror the engine's whole catalogue into ``Analyzer``; returns the number synced."""
    return sync_connector_catalog(connector_name, registry.instantiate(connector_name))


def sync_connector_catalog(name: str, connector) -> int:
    """sync_catalog for an already built connector. A fetch failure propagates."""
    from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
    from cortex_job.migrations._tier_seed import tier_for
    from cortex_job.models import Analyzer

    offered = connector.catalog()
    if not offered:
        return 0

    synced, ai_name = [], ai_analyzer_name()
    with transaction.atomic():
        for entry in offered:
            if entry.name == ai_name:
                continue  # the AI vote's row belongs to its own engine: never created or claimed here
            owner = Analyzer.objects.filter(name=entry.name).values_list("source", flat=True).first()
            if owner is not None and owner != name:
                # Analyzer.name is unique across sources: another connector owns this one.
                log_sync.error("%s offers analyzer %r but it belongs to %r; skipped.", name, entry.name, owner)
                continue
            try:
                analyzer_id = ledger_ids(name, "", str(entry.id))[1]
            except ValueError:
                log_sync.error("%s analyzer %r: id too long; skipped.", name, entry.name)
                continue
            defaults = {"analyzer_cortex_id": analyzer_id, "is_active": True, "source": name}
            Analyzer.objects.update_or_create(
                name=entry.name, defaults=defaults, create_defaults={**defaults, "tier": tier_for(entry.name)},
            )
            synced.append(entry.name)
        # The AI vote's row (ai_model connector) is no engine analyzer: leave it active.
        Analyzer.objects.filter(source=name).exclude(name__in=[*synced, ai_name]).update(is_active=False)

    if name == "cortex":
        _warn_on_unresolved_configured_analyzers(synced)
    return len(synced)


def _warn_on_unresolved_configured_analyzers(offered_names: list[str]) -> None:
    """integrations.cortex.analyzers.{header,sandbox,yara,file_info} are plain names that
    dispatch looks up at start time; a miss there is one warning among hundreds (this is how
    "header": "MailHeader_4_0" once sat wrong unnoticed). Cross-check them against the
    catalogue just fetched, which is the authoritative current set, and log loudly."""
    try:
        from settings.config import get_section
        configured = get_section("integrations.cortex").get("analyzers", {}) or {}
    except Exception as exc:  # noqa: BLE001
        log_sync.error("Could not load integrations.cortex.analyzers to validate: %s", exc)
        return

    offered = set(offered_names)
    for role, name in configured.items():
        # ai names the AI vote's Analyzer row (ai_model connector), not an engine analyzer.
        if role != "ai" and name and name not in offered:
            log_sync.error(
                "integrations.cortex.analyzers.%s = %r does not match any analyzer "
                "currently enabled in Cortex; dispatch for this role will silently "
                "find nothing every time. Check the analyzer's real registered name "
                "(Cortex organization analyzer list) against settings.json.",
                role, name,
            )
