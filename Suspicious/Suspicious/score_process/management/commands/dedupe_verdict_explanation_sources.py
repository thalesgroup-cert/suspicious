"""Recompute Case.verdict_explanation for already-finalized cases whose
"sources" list was built from an undeduplicated AnalyzerReport queryset
(fixed in score_process/scoring/{apply.py,cortex_analyzers/reports.py}) --
a rerun leaves the old report row in place, so a case that was reanalyzed
ended up with one source row per historical run instead of one per
(analyzer, target).

Never re-derives the verdict: reuses the already-locked band/confidence
(Case.results/final_confidence) and decisive_rule (already stored in the
explanation). Only rebuilds the source list and the paragraph text that
depends on its size/counted-count.

Skips multi-observable IOC-group cases (an observable_group with more than
one artifact): their analyst/reporter text embeds an observable-count this
command cannot safely reconstruct without re-deriving the original
per-observable verdicts -- these are reported for manual review, never
guessed at.
"""
from django.core.management.base import BaseCommand

from api.utils.analyzer_reports import reports_for_case
from api.views.investigations import _dedup_analyzer_reports
from case_handler.models import Case
from score_process.scoring.explanation.adapters import (
    _build, _case_data_type, _missing_phrase, _norm_band, _source_lines,
)

BATCH = 500


def _needs_manual_review(case) -> bool:
    group = getattr(case, "observable_group", None)
    return bool(group and group.artifacts.count() > 1)


def _repair(case):
    """(new_verdict_explanation_dict, old_source_count, new_source_count),
    or None if the case isn't actually improved by a recompute (already
    deduped, or malformed/empty explanation)."""
    ve = case.verdict_explanation
    if not ve:
        return None
    old_sources = ve.get("sources") or []
    rule = ve.get("decisive_rule") or "unknown"
    band = _norm_band(case.results)
    confidence = int(case.final_confidence or 0)

    deduped_reports = _dedup_analyzer_reports(reports_for_case(case))
    source_lines = _source_lines(rule, deduped_reports)

    if len(source_lines) >= len(old_sources):
        return None

    new_ve = _build(
        rule, band, confidence, source_lines,
        _case_data_type(case), _missing_phrase(case.inconclusive_reason),
    )
    return new_ve.to_dict(), len(old_sources), len(source_lines)


class Command(BaseCommand):
    help = (
        "Recompute verdict_explanation.sources for cases whose sources were "
        "built before the AnalyzerReport dedup fix landed."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)
        parser.add_argument(
            "--case-id", type=int, default=None,
            help="Repair just this one case (still respects --dry-run).",
        )

    def handle(self, *args, **opts):
        qs = (
            Case.objects
            .filter(verdict_explanation__isnull=False)
            .select_related("observable_group")
            .order_by("id")
        )
        if opts["case_id"]:
            qs = qs.filter(pk=opts["case_id"])
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = repaired = skipped_clean = skipped_review = 0
        review_ids = []
        batch = []

        for case in qs.iterator(chunk_size=BATCH):
            scanned += 1
            if _needs_manual_review(case):
                skipped_review += 1
                review_ids.append(case.id)
                continue

            result = _repair(case)
            if result is None:
                skipped_clean += 1
                continue

            new_dict, old_n, new_n = result
            self.stdout.write(f"case {case.id}: {old_n} -> {new_n} sources")
            repaired += 1
            if not opts["dry_run"]:
                case.verdict_explanation = new_dict
                batch.append(case)
                if len(batch) >= BATCH:
                    Case.objects.bulk_update(batch, ["verdict_explanation"])
                    batch = []

        if batch:
            Case.objects.bulk_update(batch, ["verdict_explanation"])

        verb = "would repair" if opts["dry_run"] else "repaired"
        ids_preview = review_ids[:20]
        suffix = "..." if len(review_ids) > 20 else ""
        self.stdout.write(
            f"scanned {scanned}, {verb} {repaired}, already clean {skipped_clean}, "
            f"needs manual review {skipped_review} (case ids: {ids_preview}{suffix})"
        )
