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
    """Run the enabled ``kind`` provider for one case and close its ledger row.
    Only a retryable ProviderUnavailable is retried; anything else (an open
    breaker, a disabled provider, a 4xx) finishes the row as failure at once."""
    from common.http_client import get_breaker
    from connectors.providers import (
        ProviderUnavailable, finish_provider_analysis, provider_connector,
    )
    from cortex_job.models import CaseAnalyzerJob

    if not CaseAnalyzerJob.objects.filter(
        pk=job_id, status__in=CaseAnalyzerJob.PENDING_STATUSES
    ).exists():
        return  # closed already (redelivery, or fail_stale_jobs got there first)
    started = time.monotonic()
    name, result, error = kind, None, "provider returned no result"
    try:
        connector = provider_connector(kind)
        name = connector.manifest.name
        with get_breaker(name).calling():
            result = connector.analyze(kind, case_id)
    except ProviderUnavailable as exc:
        if exc.retryable and self.request.retries < self.max_retries:
            raise self.retry(
                exc=exc, countdown=5 * 2 ** self.request.retries + random.uniform(0, 3)
            )
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 — connector code is untrusted
        error = f"{type(exc).__name__}: {exc}"
    ledger = dict(attempt=self.request.retries + 1, connector=name,
                  duration_ms=int((time.monotonic() - started) * 1000))
    if result is not None:
        try:
            finish_provider_analysis(job_id, result, **ledger)
            return
        except Exception as exc:  # noqa: BLE001 — a bad result must not strand the case
            error = f"could not store the result: {type(exc).__name__}: {exc}"
    finish_provider_analysis(job_id, None, error=error, **ledger)


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
