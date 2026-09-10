"""Backfill Case.verdict_explanation for finalized cases created before the
verdict-explanation feature. Composes a best-effort generic (rule="unknown")
explanation from already-stored case state — does NOT re-run the scoring
engine. Display-only and idempotent."""
from django.core.management.base import BaseCommand

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case
from cortex_job.cortex_utils.case_targets import (
    build_analyzer_report_filter,
    collect_case_targets,
)
from cortex_job.models import AnalyzerReport
from score_process.scoring.explanation.adapters import _norm_band
from score_process.scoring.explanation.compose import compose
from score_process.scoring.explanation.types import SourceLine, VerdictExplanation
from score_process.scoring.sources import source_verdict_from_report

BATCH = 500


def _build(case) -> VerdictExplanation:
    band = _norm_band(case.results)
    conf = int(case.final_confidence or 0)
    targets = collect_case_targets(case)
    reports = (
        AnalyzerReport.objects.filter(build_analyzer_report_filter(targets))
        .select_related("analyzer")
        if targets else []
    )
    lines = []
    for r in reports:
        sv = source_verdict_from_report(r)
        lines.append(SourceLine(
            name=r.analyzer.name,
            tier=sv.tier,
            verdict="failed" if sv.failed else sv.verdict,
            counted=False,  # generic: no decisive rule recovered
            note=(sv.evidence or "")[:60],
        ))
    lines.sort(key=lambda s: (s.tier, s.name))
    facts = dict(source="a source", n_context=len(lines), n_counted=0,
                 n_total=len(lines), data_type="indicator",
                 missing="coverage is thin", share=0.0)
    analyst, reporter, reading = compose("unknown", band, conf, lines, **facts)
    return VerdictExplanation(band, conf, "unknown", analyst, reporter, reading,
                              tuple(lines))


class Command(BaseCommand):
    help = "Populate Case.verdict_explanation for finalized cases that have none."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)

    def handle(self, *args, **opts):
        qs = (Case.objects
              .filter(verdict_explanation__isnull=True,
                      lifecycle_state=LifecycleState.FINALIZED)
              .order_by("id"))
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = written = 0
        batch = []
        for case in qs.iterator(chunk_size=BATCH):
            scanned += 1
            case.verdict_explanation = _build(case).to_dict()
            batch.append(case)
            if len(batch) >= BATCH and not opts["dry_run"]:
                Case.objects.bulk_update(batch, ["verdict_explanation"])
                written += len(batch)
                batch = []
        if batch and not opts["dry_run"]:
            Case.objects.bulk_update(batch, ["verdict_explanation"])
            written += len(batch)

        if opts["dry_run"]:
            self.stdout.write(
                f"scanned {scanned}, would write {scanned} verdict_explanation rows")
        else:
            self.stdout.write(
                f"scanned {scanned}, wrote {written} verdict_explanation rows")
