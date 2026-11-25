import random
import time

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=2, acks_late=True)


@shared_task(bind=True, **_RETRY)
def deliver_event(self, connector_name: str, event_name: str, payload: dict, deferrals: int = 0):
    from connectors.delivery import (
        MAX_ATTEMPTS, MAX_DEFERRALS, DeliverLater, RetryableDeliveryError, deliver_now,
    )
    # Deferrals are not attempts: only the retries beyond them count.
    attempt = max(1, self.request.retries - deferrals + 1)
    budget = MAX_DEFERRALS + MAX_ATTEMPTS
    try:
        deliver_now(connector_name, event_name, payload, attempt=attempt, deferrals=deferrals)
    except DeliverLater as later:
        raise self.retry(exc=later, countdown=later.countdown, max_retries=budget,
                         kwargs={"deferrals": deferrals + 1})
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=30 * 2 ** (attempt - 1), max_retries=budget,
                         kwargs={"deferrals": deferrals})


@shared_task(bind=True, **_RETRY)
def run_connector_sync(self, connector_name: str):
    from connectors.delivery import RetryableDeliveryError, run_sync_now
    try:
        run_sync_now(connector_name, attempt=self.request.retries + 1)
    except RetryableDeliveryError as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=2)
def run_provider_analysis(self, case_id: int, kind: str, job_id: int):
    """Forwarder for mail AI jobs queued by the old provider slot before the upgrade: remove after
    the next release. ``job_id`` is the pk of the report-less ``provider-`` row the old code opened;
    it runs as a deferred job of ai_model."""
    # Always ai_model, whatever the row's analyzer source: every provider- row came from the
    # mail_ai slot, whose only implementer was ai_model (a Cortex-owned AI row must never reach
    # Cortex's run, nor its breaker).
    _run_deferred_job(self, job_id, engine="ai_model")


@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=2)
def run_engine_job(self, row_id: int):
    """Run one deferred engine job (StartResult.deferred) and close its ledger row.
    Only a retryable ProviderUnavailable is retried; anything else (an open breaker,
    an error, a result that is not one) closes the row as Failure at once. A connector
    disabled since the start still runs: a started job finishes."""
    _run_deferred_job(self, row_id)


def _run_deferred_job(task, row_id: int, engine: str = "") -> None:
    """The body of run_engine_job, shared with the forwarder. ``engine`` overrides the row's
    analyzer source; when it is not a registered analysis engine the row closes Failure."""
    from common.http_client import get_breaker
    from connectors.base import DATA_TYPE_MAIL_ARCHIVE, FETCH_RESULT, PROVIDER_KIND_ANALYSIS, FetchResult
    from connectors.engines import _external_job_id
    from connectors.providers import ProviderUnavailable
    from connectors.registry import registry
    from cortex_job.models import CaseAnalyzerJob

    row = (CaseAnalyzerJob.objects.select_related("analyzer")
           .filter(pk=row_id, status__in=CaseAnalyzerJob.PENDING_STATUSES).first())
    if row is None:
        return  # gone or closed already (redelivery, or fail_stale_jobs got there first)
    name, analyzer_name, case_id = row.analyzer.source, row.analyzer.name, row.case_id
    started = time.monotonic()
    if engine:
        name = engine
        if name not in registry.providers(PROVIDER_KIND_ANALYSIS):
            _close_engine_job(row_id, name, analyzer_name, None,
                              FetchResult(FETCH_RESULT, "Failure", payload={"reason": "no engine for this job"}),
                              attempt=task.request.retries + 1, duration_ms=0)
            return
    result, error, connector = None, "engine returned no result", None
    try:
        connector = registry.instantiate(name)
        with get_breaker(name).calling():
            # Every deferred job is a mail_archive job in this release; its value is the case id.
            result = connector.run(_external_job_id(name, row.cortex_job_id),
                                   DATA_TYPE_MAIL_ARCHIVE, str(case_id))
    except ProviderUnavailable as exc:
        if exc.retryable and task.request.retries < task.max_retries:
            raise task.retry(
                exc=exc, countdown=5 * 2 ** task.request.retries + random.uniform(0, 3)
            )
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 — connector code is untrusted
        error = f"{type(exc).__name__}: {exc}"
    if result is not None and (result.state != FETCH_RESULT or result.status not in ("Success", "Failure")):
        error, result = f"not a result (state {result.state!r}, status {result.status!r})", None
    if result is None:
        result = FetchResult(FETCH_RESULT, "Failure", payload={"reason": error})
    _close_engine_job(row_id, name, analyzer_name, connector, result, attempt=task.request.retries + 1,
                      duration_ms=int((time.monotonic() - started) * 1000))


def _close_engine_job(row_id, name, analyzer_name, connector, result, *, attempt, duration_ms) -> None:
    from django.db import transaction
    from django.utils import timezone

    from case_handler.models import Case
    from connectors.models import ConnectorDelivery
    from cortex_job.models import CaseAnalyzerJob
    from tasp.tasks import reconcile_case

    success = result.status == "Success"
    error = str((result.payload or {}).get("reason") or "")
    with transaction.atomic():
        # The conditional UPDATE claims the row: a redelivered or racing run finds nothing to close.
        claimed = CaseAnalyzerJob.objects.filter(
            pk=row_id, status__in=CaseAnalyzerJob.PENDING_STATUSES
        ).update(status=CaseAnalyzerJob.STATUS_SUCCESS if success else CaseAnalyzerJob.STATUS_FAILURE,
                 completed_at=timezone.now())
        if not claimed:
            return
        case = Case.objects.get(analyzer_jobs__pk=row_id)
        if connector is not None:  # None only when the connector could not be built
            try:
                with transaction.atomic():  # a savepoint: a failing hook leaves nothing half-written
                    connector.on_result(case, analyzer_name, result)
            except Exception as exc:  # noqa: BLE001: the class name only, a message may carry data
                logger.error("Engine %s on_result for case %s failed: %s", name, case.id, type(exc).__name__)
                error = f"could not store the result: {type(exc).__name__}"
                success = False
                CaseAnalyzerJob.objects.filter(pk=row_id).update(status=CaseAnalyzerJob.STATUS_FAILURE)
        ConnectorDelivery.objects.create(
            connector=name, event="analyze", case_id=case.id,
            status=ConnectorDelivery.STATUS_SUCCESS if success else ConnectorDelivery.STATUS_FAILED,
            error=error[:5000], attempt=attempt, duration_ms=duration_ms,
        )
        transaction.on_commit(lambda: reconcile_case.delay(case.id))


_mismatch_warned = False


def _warn_collection_mismatch(profile) -> None:
    """Log the cleanup/collection mismatch once per process. Never raises: it must not fail or
    retry a detection. Checked again on later runs until it has been logged."""
    global _mismatch_warned
    if _mismatch_warned:
        return
    try:
        from connectors.contrib.ai_model.campaigns import collection_mismatch

        sentence = collection_mismatch(profile.collection_name)
        if sentence:
            logger.warning(sentence)
            _mismatch_warned = True
    except Exception as exc:  # noqa: BLE001
        logger.debug("Collection mismatch check failed: %s", type(exc).__name__)


@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=3)
def run_campaign_detection(self, case_id: int) -> None:
    """Place one finalised case in a campaign (ai_model) and emit campaign_updated when it
    joined, created or is already in one (a redelivery announces it again).

    Queued by the connector's case_finalised hook rather than run in it: the hook runs under the
    ai_model breaker, which the classification calls share, and a Chroma outage must not open it.
    detect_campaign raises only before the campaign rows exist, so every failure but a
    non-retryable ProviderUnavailable is retried. A case already placed is announced even when
    the collection cannot be opened, then retried for its store and tag steps (each try announces
    it again; the last one just ends). Only the exception class is logged: a message can carry
    mail text."""
    from ai_model.campaign_profile import current_profile
    from case_handler.models import CampaignMember, Case
    from connectors.base import EVENT_CAMPAIGN_UPDATED
    from connectors.contrib.ai_model.campaigns import (
        CampaignStoreUnavailable, detect_campaign, open_collection,
    )
    from connectors.contrib.ai_model.mailtext import (
        header_dict, mail_archive_for, read_archive_material,
    )
    from connectors.dispatch import emit
    from connectors.providers import ProviderUnavailable

    try:
        try:
            case = Case.objects.select_related("fileOrMail__mail", "ai_assessment").get(pk=case_id)
        except Case.DoesNotExist:
            logger.info("Case %s no longer exists, no campaign detection.", case_id)
            return
        assessment = getattr(case, "ai_assessment", None)
        archive = mail_archive_for(case) if assessment else None
        material = read_archive_material(archive) if archive else None
        if material is None:
            logger.info("Case %s: no AI assessment or mail text, no campaign detection.", case_id)
            return
        profile = current_profile()
        _warn_collection_mismatch(profile)
        try:
            headers = header_dict(material.headers)
        except Exception as exc:  # noqa: BLE001 — a malformed header must not stop detection
            logger.warning("Case %s: unreadable headers (%s), detecting without them.",
                           case_id, type(exc).__name__)
            headers = {}
        try:
            collection = open_collection(profile)
        except CampaignStoreUnavailable as exc:
            member = CampaignMember.objects.filter(case=case).only("campaign_id").first()
            if member is None:
                raise
            logger.warning("Case %s: campaign store down (%s), announcing campaign %s without it.",
                           case_id, type(exc).__name__, member.campaign_id)
            emit(EVENT_CAMPAIGN_UPDATED, case, campaign_id=member.campaign_id)
            if self.request.retries >= self.max_retries:
                return
            # Retried for the store and tag steps; the retry announces it once more.
            failure, retryable = type(exc).__name__, True
        else:
            campaign = detect_campaign(case, assessment, material.text, headers, profile, collection)
            if campaign is not None:
                emit(EVENT_CAMPAIGN_UPDATED, case, campaign_id=campaign.id)
            return
    except Exception as exc:  # noqa: BLE001 — a lock or cache outage arrives as any type
        failure = type(exc).__name__
        retryable = not isinstance(exc, ProviderUnavailable) or exc.retryable
    # Retried outside the except block, so the retry does not chain the original exception.
    if retryable and self.request.retries < self.max_retries:
        logger.warning("Campaign detection for case %s failed (%s), retrying.", case_id, failure)
        raise self.retry(countdown=30 * 2 ** self.request.retries)
    logger.error("Campaign detection for case %s failed: %s", case_id, failure)


@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=3)
def run_shadow_campaign(self, case_id: int) -> None:
    """Ruling F7: record what campaign detection would do with the shadow's class for one finalised
    case (connectors.contrib.ai_model.dryrun). Writes only a ShadowCampaignEffect row: no Campaign,
    no live collection write, no event. Retried as run_campaign_detection; only the exception class
    is logged."""
    from ai_model.campaign_profile import current_profile
    from ai_model.models import AiAssessment, ModelVersion, ShadowResult
    from connectors.contrib.ai_model.campaigns import open_collection
    from connectors.contrib.ai_model.dryrun import dry_run_campaign
    from connectors.contrib.ai_model.mailtext import (
        header_dict, mail_archive_for, read_archive_material,
    )

    try:
        row = ShadowResult.objects.select_related("case__fileOrMail__mail", "version").filter(
            case_id=case_id, version__status=ModelVersion.Status.SHADOW, error="").first()
        assessment = AiAssessment.objects.filter(case_id=case_id).first() if row else None
        archive = mail_archive_for(row.case) if assessment else None
        material = read_archive_material(archive) if archive else None
        if material is None:
            logger.info("Case %s: no shadow answer, AI assessment or mail, no shadow campaign check.", case_id)
            return
        try:
            headers = header_dict(material.headers)
        except Exception as exc:  # noqa: BLE001 — as run_campaign_detection
            logger.warning("Case %s: unreadable headers (%s), dry run without them.", case_id, type(exc).__name__)
            headers = {}
        profile = current_profile()
        # A case the candidate does not call Dangerous needs no collection: Chroma down cannot hold it.
        collection = open_collection(profile) if row.result == profile.trigger_class else None
        dry_run_campaign(row.case, row, assessment, headers, profile, collection)
        return
    except Exception as exc:  # noqa: BLE001
        failure = type(exc).__name__
    if self.request.retries < self.max_retries:
        logger.warning("Shadow campaign check for case %s failed (%s), retrying.", case_id, failure)
        raise self.retry(countdown=30 * 2 ** self.request.retries)
    logger.error("Shadow campaign check for case %s failed: %s", case_id, failure)
