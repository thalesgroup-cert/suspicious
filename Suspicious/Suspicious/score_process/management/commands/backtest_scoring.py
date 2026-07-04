"""Replay finalised cases through the new scoring engine and report verdict
drift against the stored (old-engine) verdict. Read-only: never writes a Case.

The stored ``Case.results`` already IS the old engine's output, so this diffs
new-engine output against the recorded old verdict directly. Signals are
rebuilt per-AnalyzerReport from the CaseAnalyzerJob ledger (a coarser
granularity than live collect_signals, which aggregates per artifact) — good
enough to compare verdict bands, which is the point. Safe↔Dangerous flips get
eyeballed by the operator, not trusted blindly.
"""
from collections import Counter

from django.core.management.base import BaseCommand

from case_handler.models import Case
from cortex_job.models import CaseAnalyzerJob
from score_process.scoring.engine import (
    Signal, score_case, MALICIOUS_SCORE_THRESHOLD,
)


def _signals_for(case):
    """Rebuild Signals from a case's ledger-linked AnalyzerReports (read-only)."""
    signals = []
    rows = (
        CaseAnalyzerJob.objects
        .filter(case=case)
        .select_related("analyzer_report")
    )
    for caj in rows:
        report = caj.analyzer_report
        if report is None:
            continue
        if report.status == "Failure":
            signals.append(Signal("report", 0, 0, False, True))
            continue
        if report.status != "Success":
            continue
        score = report.score or 0
        conf = min(report.confidence or 0, 100)   # AnalyzerReport.confidence is 0–100
        is_mal = (report.level or "").lower() in ("malicious", "dangerous") \
            or score >= MALICIOUS_SCORE_THRESHOLD
        signals.append(Signal("report", score, conf, is_mal, False))
    return signals


class Command(BaseCommand):
    help = "Backtest the new scoring engine against stored case verdicts (read-only)."

    def handle(self, *args, **options):
        matrix = Counter()
        n = 0
        self.stdout.write("case_id  old -> new  (new_score)")
        for case in Case.objects.exclude(results="").iterator():
            signals = _signals_for(case)
            verdict = score_case(signals)
            old, new = case.results, verdict.result
            matrix[(old, new)] += 1
            n += 1
            if old != new:
                self.stdout.write(f"{case.id}  {old} -> {new}  ({verdict.final_score})")
        self.stdout.write("\nTransition matrix (old -> new: count):")
        for (old, new), count in sorted(matrix.items()):
            flag = "" if old == new else "  <-- CHANGED"
            self.stdout.write(f"  {old} -> {new}: {count}{flag}")
        self.stdout.write(f"\nScored {n} cases.")
