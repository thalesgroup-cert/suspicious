"""Analysis-provider slot: resolve which connector supplies a kind of analysis,
queue a case to it and write its result back like the Cortex AI job did."""
from __future__ import annotations

import logging
from uuid import uuid4

from django.db import transaction
from django.utils import timezone

from connectors.registry import registry

logger = logging.getLogger("connectors.delivery")

PROVIDER_JOB_PREFIX = "provider-"


class ProviderUnavailable(Exception):
    """Raised by ``Connector.analyze`` when the provider cannot answer. A retryable
    error (connection, timeout, 5xx) is retried by the task; any other fails at once."""

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def enabled_provider(kind: str) -> str | None:
    """Name of the enabled connector providing ``kind``, or None. At most one
    can be enabled (the connector state API refuses a second)."""
    from connectors.delivery import get_state  # lazy: delivery imports the registry too

    return next(
        (name for name in registry.providers(kind) if get_state(name).enabled), None
    )


def provider_connector(kind: str):
    """Instance of the enabled ``kind`` provider; ProviderUnavailable when none is."""
    name = enabled_provider(kind)
    if name is None:
        raise ProviderUnavailable(f"no enabled {kind} provider", retryable=False)
    return registry.instantiate(name)


def queue_provider_analysis(case, kind: str):
    """Hand ``case`` to the enabled ``kind`` provider: a pending ledger row for the
    AI analyzer (reconcile waits for it) and the task, enqueued on commit.
    None when no provider is enabled."""
    if enabled_provider(kind) is None:
        return None
    from connectors.tasks import run_provider_analysis
    from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
    from cortex_job.migrations._tier_seed import tier_for
    from cortex_job.models import Analyzer, CaseAnalyzerJob

    ai_name = ai_analyzer_name()
    analyzer, _ = Analyzer.objects.get_or_create(
        name=ai_name,
        defaults={"analyzer_cortex_id": "provider:" + ai_name, "tier": tier_for(ai_name)},
    )
    job = CaseAnalyzerJob.objects.create(
        case=case,
        cortex_job_id=PROVIDER_JOB_PREFIX + uuid4().hex[:30],
        analyzer=analyzer,
        status=CaseAnalyzerJob.STATUS_INPROGRESS,
    )
    # Only finish_provider_analysis replaces this: a row closed any other way (fail_stale_jobs,
    # a lost or failed enqueue) leaves the AI missing, not at the model default "Suspicious".
    # A case with an earlier assessment keeps that row's fields until this row succeeds: they
    # come from a real answer, and marking them missing now would lose them if this row fails.
    if not has_assessment(case):
        mark_ai_missing(case)
    transaction.on_commit(lambda: run_provider_analysis.delay(case.id, kind, job.id))
    return job


def has_assessment(case) -> bool:
    """True when an earlier provider row for the case succeeded (its AiAssessment is stored)."""
    from ai_model.models import AiAssessment

    return AiAssessment.objects.filter(case=case).exclude(model_version="").exists()


def mark_ai_missing(case) -> None:
    """No AI result will come: what the Cortex path wrote when its AI job failed or never ran,
    so scoring treats the AI vote as missing (``ai_missing``) instead of the "Suspicious" default."""
    from case_handler.models import Result

    case.results_ai = Result.INCONCLUSIVE
    case.save(update_fields=["results_ai"])


def queue_mail_ai(case):
    """Hand a mail with a readable archive to the mail_ai provider; with none enabled, mark the
    AI missing. Returns the ledger row or None."""
    from connectors.base import PROVIDER_KIND_MAIL_AI

    job = queue_provider_analysis(case, PROVIDER_KIND_MAIL_AI)
    if job is None:
        mark_ai_missing(case)
    return job


def finish_provider_analysis(job_id: int, result, *, error: str = "", attempt: int = 1,
                             duration_ms: int = 0, connector: str = "") -> bool:
    """Write ``result`` (None = failure) to the case, close the ledger row and
    enqueue reconcile. False, and nothing written, when the row is already closed.

    A result without a model_version (the provider's "no answer": unreadable mail, a refusal) is
    a failure. A failure keeps the case's assessment and AI fields from an earlier successful row
    of the case, else leaves the AI missing (Inconclusive)."""
    from ai_model.mailinfo import apply_mail_info
    from ai_model.models import AiAssessment
    from case_handler.models import Case, Result
    from connectors.models import ConnectorDelivery
    from cortex_job.models import CaseAnalyzerJob
    from mail_feeder.models import MailInfo
    from tasp.tasks import reconcile_case

    if result is not None and not result.model_version:
        error = f"no model_version ({result.reason})" if result.reason else "no model_version"
        result = None
    status = CaseAnalyzerJob.STATUS_FAILURE if result is None else CaseAnalyzerJob.STATUS_SUCCESS
    with transaction.atomic():
        # The conditional UPDATE claims the row: a redelivered task finds nothing left to close.
        claimed = CaseAnalyzerJob.objects.filter(
            pk=job_id, status__in=CaseAnalyzerJob.PENDING_STATUSES
        ).update(status=status, completed_at=timezone.now())
        if not claimed:
            return False
        case = Case.objects.get(analyzer_jobs__pk=job_id)
        if result is not None:
            case.results_ai = result.result.capitalize()
            case.score_ai = result.score
            case.confidence_ai = result.confidence
            case.category_ai = result.category[:Case._meta.get_field("category_ai").max_length]
            case.save(update_fields=["results_ai", "score_ai", "confidence_ai", "category_ai"])
            mail = getattr(case.fileOrMail, "mail", None)
            mail_info = MailInfo.objects.filter(mail=mail).first() if mail else None
            apply_mail_info(mail_info, case.category_ai, case.results_ai)
        elif not has_assessment(case):
            case.results_ai = Result.INCONCLUSIVE
            case.save(update_fields=["results_ai"])
        if result is None:
            logger.warning("mail AI provider failed for case %s: %s", case.id, error)
        else:
            # Every field, the model's default where the result has none: nothing of an older
            # assessment survives under the new result.
            fresh = {f.name: f.get_default() for f in AiAssessment._meta.concrete_fields
                     if not f.primary_key and f.name not in ("case", "created_at", "updated_at")}
            AiAssessment.objects.update_or_create(case=case, defaults={
                **fresh,
                **result.assessment,
                "model_version": result.model_version,
                "result": result.result,
                "score": result.score,
                "confidence": result.confidence,
            })
        ConnectorDelivery.objects.create(
            connector=connector, event="analyze", case_id=case.id,
            status=ConnectorDelivery.STATUS_FAILED if result is None
            else ConnectorDelivery.STATUS_SUCCESS,
            error=(error if result is None else result.reason)[:5000],
            attempt=attempt, duration_ms=duration_ms,
        )
        transaction.on_commit(lambda: reconcile_case.delay(case.id))
    if result is not None and result.shadow is not None:
        from ai_model.shadow import store_shadow_result

        try:
            store_shadow_result(case, result.shadow)
        except Exception as exc:  # noqa: BLE001 -- a shadow problem never touches the live case
            logger.warning("shadow result not stored for case %s: %s", case.id, type(exc).__name__)
    return True
