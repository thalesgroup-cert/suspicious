"""Celery tasks of the retrain (ai_model.retrain). Short tasks only: training runs in the inference
server, so no task outlives the broker's visibility timeout."""
import logging
from time import monotonic  # module-level so tests can patch the clock

from celery import shared_task

logger = logging.getLogger(__name__)

SEED_CHUNK = 25
SEED_BUDGET_SECONDS = 20 * 60  # Ruling F8; checked between chunks
SEED_RETRY_SECONDS = 300


@shared_task
def poll_retrain(job_id: str) -> None:
    """One status check; queued again while the job runs (MAX_AGE ends it). The re-queue is in a
    finally, so an error in this run does not end the chain while the job is still running; a
    chain that keeps raising past MAX_AGE + STOP_MARGIN stops and fails the job (class name)."""
    from django.db import DatabaseError
    from django.utils import timezone

    from ai_model import retrain
    from ai_model.models import RetrainJob

    error = "TimedOut"
    try:
        retrain.poll_once(job_id)
    except Exception as exc:
        error = type(exc).__name__
        raise
    finally:
        try:
            job = RetrainJob.objects.filter(job_id=job_id, state=RetrainJob.State.RUNNING).first()
            stale = job is not None and timezone.now() - job.started_at > retrain.MAX_AGE + retrain.STOP_MARGIN
        except DatabaseError:
            job, stale = True, False  # the database is away: ask again, the row decides next time
        if stale:
            retrain.give_up(job, error)
        elif job is not None:
            poll_retrain.apply_async((job_id,), countdown=retrain.poll_countdown())


@shared_task
def maybe_start_retrain() -> None:
    """Daily (beat entry in connectors.apps): a no-op unless retrain_enabled (Ruling E10)."""
    from ai_model import retrain

    retrain.maybe_start()


@shared_task
def sync_server() -> None:
    """Every 300 s (beat entry in connectors.apps): push the registry state to the inference server
    when they differ. A no-op while the connector is disabled or has no usable token or url."""
    from connectors.registry import registry

    from ai_model import ledger, serversync

    if not ledger.enabled():
        return
    try:
        client = registry.instantiate("ai_model")._client()
    except ValueError:
        return
    try:
        serversync.sync(client)
    except serversync.ReloadRefused as exc:
        logger.warning("ai_model server sync refused: %s", type(exc).__name__)


# A run ends after the budget plus at most one chunk (25 classify calls under the connector's
# timeout), so the task's own limits replace the global 540 s soft limit.
@shared_task(soft_time_limit=SEED_BUDGET_SECONDS + 600, time_limit=SEED_BUDGET_SECONDS + 660)
def seed_shadow(version_id: str, offset: int = 0) -> None:
    """Ruling F8: classify the live collection's documents with the shadow and store origin="seed"
    ShadowResult rows. Pages the collection SEED_CHUNK documents at a time from ``offset`` and
    queues itself again with the next offset once SEED_BUDGET_SECONDS are spent. A document
    without a case-<id> id or whose case is gone is skipped, so is a case that already has a row
    of this version (a rerun classifies nothing twice and never overwrites a live row). A no-op
    once the version is no longer the shadow. No document text is logged."""
    from connectors.contrib.ai_model.campaigns import CampaignStoreUnavailable, open_collection
    from connectors.providers import ProviderUnavailable
    from connectors.registry import registry

    from ai_model import ledger, serversync
    from ai_model.campaign_profile import current_profile
    from ai_model.models import ModelVersion

    version = ModelVersion.objects.filter(version_id=version_id, status=ModelVersion.Status.SHADOW).first()
    if version is None or not ledger.enabled():
        return
    started = monotonic()
    try:
        client = registry.instantiate("ai_model")._client()
        # The server must hold the shadow before ["shadow"] answers (409 otherwise).
        if not serversync.sync(client):
            raise ProviderUnavailable("registry and server differ")
        collection = open_collection(current_profile())
        while monotonic() - started < SEED_BUDGET_SECONDS:
            page = collection.get(limit=SEED_CHUNK, offset=offset, include=["documents"])
            ids = page.get("ids") or []
            for doc_id, text in zip(ids, page.get("documents") or []):
                _seed_one(version, doc_id, text, client)
            offset += len(ids)
            if len(ids) < SEED_CHUNK:
                logger.info("Shadow %s seeded up to offset %d.", version_id, offset)
                return
        seed_shadow.apply_async((version_id, offset))
    except (ValueError, serversync.ReloadRefused) as exc:  # token/url missing or reload refused
        logger.warning("Shadow seeding of %s stopped: %s", version_id, type(exc).__name__)
    except (ProviderUnavailable, CampaignStoreUnavailable) as exc:
        if isinstance(exc, ProviderUnavailable) and not exc.retryable:
            logger.warning("Shadow seeding of %s stopped: %s", version_id, type(exc).__name__)
            return
        logger.warning("Shadow seeding of %s paused at %d (%s).", version_id, offset, type(exc).__name__)
        seed_shadow.apply_async((version_id, offset), countdown=SEED_RETRY_SECONDS)


def _seed_one(version, doc_id, text, client) -> None:
    """One document; a refused mail or a malformed answer skips it. ProviderUnavailable propagates
    (the run pauses)."""
    from case_handler.models import Case

    from ai_model.models import ShadowResult
    from ai_model.shadow import store_shadow_result

    prefix, _, raw = str(doc_id).partition("-")
    if prefix != "case" or not raw.isdigit() or not text:
        return
    case = Case.objects.filter(pk=int(raw)).first()
    if case is None or ShadowResult.objects.filter(case=case, version=version).exists():
        return
    try:
        answer = client.classify(text, versions=("shadow",))["results"]["shadow"]
        if "error" not in answer:
            store_shadow_result(case, answer, origin=ShadowResult.Origin.SEED)
    except (ValueError, KeyError, TypeError) as exc:  # refused (4xx) or garbage: this mail only
        logger.warning("Shadow seeding skipped case %s: %s", case.id, type(exc).__name__)
