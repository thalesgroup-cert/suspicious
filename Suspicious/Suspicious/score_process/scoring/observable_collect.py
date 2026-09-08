"""Gather, per observable in a case's ObservableGroup, the SourceVerdict list
from its finished AnalyzerReports (newest report per analyzer)."""
from __future__ import annotations

from score_process.scoring.sources import source_verdict_from_report

_FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}


def _bucket_reports(triples: list[tuple]) -> dict:
    """triples: (key, obj, field), field in {"url","ip","hash","domain","mail"}.
    One AnalyzerReport query, bucketed in Python by FK id, newest first, folding
    each URL's ``analyzed_url`` representative into the same key (that URL carries
    no reports of its own — they are filed against the representative it points
    to). Returns {key: [AnalyzerReport, ...]}."""
    from cortex_job.models import AnalyzerReport
    from cortex_job.cortex_utils.case_targets import build_analyzer_report_filter

    if not triples:
        return {}

    # (field, pk) -> key so a report on a URL's analysed representative buckets
    # to the observable the analyst submitted.
    pk_to_key: dict[tuple, object] = {}
    targets = []
    for (key, obj, field) in triples:
        pk_to_key[(field, obj.pk)] = key
        targets.append((obj, field))
        rep = getattr(obj, "analyzed_url", None) if field == "url" else None
        if rep is not None:
            pk_to_key[(field, rep.pk)] = key
            targets.append((rep, field))

    q = build_analyzer_report_filter(targets)
    reports = list(
        AnalyzerReport.objects.filter(q)
        .select_related("analyzer")
        .order_by("-creation_date")
    )

    fields = {f for (_k, _o, f) in triples}
    buckets: dict = {}
    for r in reports:
        for field in fields:
            rid = getattr(r, f"{field}_id", None)
            key = pk_to_key.get((field, rid)) if rid else None
            if key is not None:
                buckets.setdefault(key, []).append(r)
                break
    return buckets


def observable_reports(case) -> list[tuple]:
    """Per group artifact: (art, obj, field, [reports]) with ONE AnalyzerReport
    query for the whole group, bucketed in Python by FK id. Reports are newest
    first. Shared by collect_observable_sources and assemble_observables so the
    detail/report paths don't issue one query per observable."""
    arts = []
    for art in case.observable_group.artifacts.select_related(
        "url", "url__analyzed_url", "ip", "hash", "domain"
    ):
        field = _FIELD[art.artifact_type]
        obj = getattr(art, field)
        if obj is not None:
            arts.append((art, obj, field))
    if not arts:
        return []

    buckets = _bucket_reports([((f, o.pk), o, f) for (_a, o, f) in arts])
    return [(art, obj, field, buckets.get((field, obj.pk), []))
            for (art, obj, field) in arts]


def collect_observable_sources(case):
    out = {}
    for art, obj, _field, reports in observable_reports(case):
        seen, verdicts = set(), []
        for r in reports:
            if r.analyzer_id in seen:
                continue
            seen.add(r.analyzer_id)
            verdicts.append(source_verdict_from_report(r))
        out[(art.artifact_type, obj.pk, obj)] = verdicts
    return out
