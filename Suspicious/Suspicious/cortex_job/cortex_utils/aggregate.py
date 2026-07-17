from dataclasses import dataclass

from django.db.models import Count

from cortex_job.models import CaseAnalyzerJob


@dataclass(frozen=True)
class CaseAggregate:
    total: int
    success: int
    failure: int
    deleted: int
    in_progress: int
    waiting: int

    @property
    def pending(self) -> int:
        return self.in_progress + self.waiting

    @property
    def scored(self) -> int:
        """Terminal, non-deleted reports — the denominator for descriptions."""
        return self.total - self.deleted


_STATUS_FIELD = {
    CaseAnalyzerJob.STATUS_SUCCESS: "success",
    CaseAnalyzerJob.STATUS_FAILURE: "failure",
    CaseAnalyzerJob.STATUS_DELETED: "deleted",
    CaseAnalyzerJob.STATUS_INPROGRESS: "in_progress",
    CaseAnalyzerJob.STATUS_WAITING: "waiting",
}


def aggregate_case(case) -> CaseAggregate:
    counts = {v: 0 for v in _STATUS_FIELD.values()}
    total = 0
    rows = (
        CaseAnalyzerJob.objects
        .filter(case=case)
        .values("status")
        .annotate(n=Count("id"))
    )
    for row in rows:
        total += row["n"]
        field = _STATUS_FIELD.get(row["status"])
        if field:
            counts[field] = row["n"]
    return CaseAggregate(total=total, **counts)
