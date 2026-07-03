# cortex_job/cortex_utils/reconciliation.py
import logging

from connectors.dispatch import emit as emit_connector_event
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _describe(results: dict) -> str:
    total = results["total"]
    n = len(total["reports"])
    success = len(total["success"])
    failure = len(total["failure"])
    deleted = len(total["deleted"])
    adjusted = n - deleted if n else 0
    if adjusted == 0:
        return (
            "No analyzer was applicable to this submission, so it could not be "
            "analysed. Check that the relevant Cortex analyzers are enabled."
        )
    if failure == 0:
        return "All analyzers completed successfully. You can now view the full results."
    if success == 0:
        return "All analyzers failed to run. Please check the configuration and retry."
    return (
        f"{success}/{adjusted} analyzers succeeded. "
        "Consider rerunning the rest for a complete analysis."
    )


def finalise(case) -> None:
    """Compute verdict + side-effects (scoring black box) and set description.

    Does NOT change status/lifecycle_state — the caller owns transitions.
    """
    mgr = CortexJobManager()
    mgr.get_results(case)               # populates mgr.results buckets
    # Verdict + KPI + connector side-effects. For zero reports this resolves to
    # the Failure verdict via update_case_results (empty-reports branch).
    CortexAnalyzerReports.get_report(case)
    case.description = _describe(mgr.results)
    case.save()


from case_handler.lifecycle import LifecycleState, transition
from cortex_job.models import CaseAnalyzerJob

_TERMINAL = {LifecycleState.FINALIZED, LifecycleState.CONTESTED}


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

    if case.lifecycle_state != LifecycleState.SCORING:
        transition(case, LifecycleState.SCORING)
    finalise(case)
    transition(case, LifecycleState.FINALIZED)
    emit_connector_event("case_finalised", case)
