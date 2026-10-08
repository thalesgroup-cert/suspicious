"""How complete the analysis behind a verdict is: which analyzers failed or are
still running. Counts the same latest report per analyzer and target that the
scoring engine sees, so it matches the confidence penalty the engine applied."""
from __future__ import annotations

from cortex_job.cortex_utils.report_target import analyzer_report_target_value

_PENDING = {"inprogress", "waiting"}
MAX_LISTED = 20


def analysis_health(reports) -> dict:
    total = failed = pending = 0
    failures: list[dict] = []
    for report in reports:
        status = (report.status or "").strip()
        low = status.lower()
        if low == "deleted":
            continue
        total += 1
        if low == "failure":
            failed += 1
            if len(failures) < MAX_LISTED:
                failures.append({
                    "analyzer": report.analyzer.name,
                    "target": analyzer_report_target_value(report) or "",
                    "status": status,
                })
        elif low in _PENDING:
            pending += 1
    return {"total": total, "failed": failed, "pending": pending, "failures": failures}
