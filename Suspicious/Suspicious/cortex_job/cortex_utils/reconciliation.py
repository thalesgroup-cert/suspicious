# cortex_job/cortex_utils/reconciliation.py
import logging
from datetime import timedelta

from django.utils import timezone

from connectors.dispatch import emit as emit_connector_event
from cortex_job.cortex_utils.aggregate import CaseAggregate, aggregate_case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _describe(agg: CaseAggregate, analysis_done: int = 0) -> str:
    if agg.scored == 0:
        # No CaseAnalyzerJob rows for this case. This is either a genuinely
        # unanalysable submission OR a deduplicated artifact whose result was
        # reused from a prior identical submission (no new job dispatched, so
        # no ledger row) — the latter still produces a scored verdict, which
        # analysis_done reflects. Don't claim "no analyzer applicable" then.
        if analysis_done > 0:
            return ("Analysis complete using results reused from a prior "
                    "identical submission.")
        return ("No analyzer was applicable to this submission, so it could "
                "not be analysed. Check that the relevant Cortex analyzers "
                "are enabled.")
    if agg.failure == 0:
        return "All analyzers completed successfully. You can now view the full results."
    if agg.success == 0:
        return "All analyzers failed to run. Please check the configuration and retry."
    return (f"{agg.success}/{agg.scored} analyzers succeeded. "
            "Consider rerunning the rest for a complete analysis.")


def finalise(case) -> None:
    """Compute verdict + side-effects (scoring black box) and set description.

    Does NOT change status/lifecycle_state — the caller owns transitions.
    """
    agg = aggregate_case(case)
    # Verdict + KPI + connector side-effects. For zero reports this resolves to
    # the Failure verdict via score_case (no scored signals → Result.FAILURE).
    # get_report writes case.analysis_done (= verdict.n_scored) on this instance.
    CortexAnalyzerReports.get_report(case)
    case.description = _describe(agg, case.analysis_done)
    case.save()


from case_handler.lifecycle import LifecycleState, transition
from cortex_job.models import CaseAnalyzerJob

_TERMINAL = {LifecycleState.FINALIZED, LifecycleState.CONTESTED}

RECONCILE_DISPATCH_GRACE = timedelta(seconds=120)


def reconcile_case_core(case) -> None:
    """Advance one case. Caller MUST hold the per-case lock."""
    if case.lifecycle_state in _TERMINAL:
        return

    mgr = CortexJobManager()
    pending = list(
        CaseAnalyzerJob.objects
        .filter(case=case, status__in=CaseAnalyzerJob.PENDING_STATUSES)
        .select_related("analyzer_report")
    )
    for caj in pending:
        mgr.update_single_job(caj)

    still_pending = CaseAnalyzerJob.objects.filter(
        case=case, status__in=CaseAnalyzerJob.PENDING_STATUSES
    ).exists()

    if still_pending:
        if case.lifecycle_state == LifecycleState.CREATED:
            transition(case, LifecycleState.ANALYZING)
        return

    # Guard against racing an in-flight dispatch: a case whose dispatch has
    # not confirmed completion (dispatched_at is None) and that is still young
    # may just be mid-dispatch (jobs not written yet). Don't finalise it — a
    # later reconcile (after dispatched_at is stamped, or once it is old enough
    # to be a genuine legacy orphan) will. This keeps the dispatch-triggered
    # reconcile finalising zero-analyzer cases promptly (dispatched_at is set
    # by then) while stopping the cron/webhook from finalising prematurely.
    if case.dispatched_at is None and case.creation_date > timezone.now() - RECONCILE_DISPATCH_GRACE:
        return

    if case.lifecycle_state != LifecycleState.SCORING:
        transition(case, LifecycleState.SCORING)
    finalise(case)
    transition(case, LifecycleState.FINALIZED)
    emit_connector_event("case_finalised", case)
