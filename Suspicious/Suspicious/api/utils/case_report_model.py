"""One data model for the downloadable case report (group, mail and file cases)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_tz

from api.utils.report_facts import (
    BAND_RANK, ConnectorLine, _VERDICT_RANK, DetailGroup, _is_vt, apply_fallbacks, connector_lines,
    detail_groups, iso_utc, key_findings, vt_facts,
)

BLOCK_CAP = 10
_MAX_FINDINGS = 5
_FLAGGED = ("Dangerous", "Suspicious")


@dataclass
class IndicatorBlock:
    type: str
    value: str
    band: str | None
    confidence: int | None
    why: list[str]
    findings: list[str]
    details: list[DetailGroup]
    connectors: list[ConnectorLine]
    vt_link: str | None
    derived_from: dict | None
    escalation_note: str = ""
    screenshot_url: str | None = None
    screenshot_data_uri: str | None = None
    screenshot_omitted: bool = False


@dataclass(frozen=True)
class IndicatorRow:
    type: str
    value: str
    band: str | None
    top_finding: str | None


@dataclass
class CaseReport:
    case_id: int
    kind: str
    band: str
    confidence: str | None
    threat: dict | None
    health: str | None
    lead: str | None
    reporter: str
    created: str | None
    generated: str
    description: str
    reporter_context: str
    why: list[str]
    ai: dict | None = None
    case_connectors: list[ConnectorLine] = field(default_factory=list)
    case_analysis: IndicatorBlock | None = None
    rows: list[IndicatorRow] = field(default_factory=list)
    blocks: list[IndicatorBlock] = field(default_factory=list)
    more: int = 0


def build_block(row: dict, *, now: datetime) -> IndicatorBlock:
    dtype, value = row["type"], str(row.get("value") or "")
    sources = row.get("sources") or []
    # a failed VirusTotal run has no trustworthy facts
    vt = next((s for s in sources if _is_vt(s) and not s.get("failed")), None) or {}
    facts = apply_fallbacks(vt_facts(vt.get("enrichment"), vt.get("report"), dtype, value), sources, dtype)
    verdict = row.get("verdict") or {}
    return IndicatorBlock(
        type=dtype, value=value, band=verdict.get("band"), confidence=verdict.get("confidence"),
        why=list(verdict.get("rationale") or []),
        findings=key_findings(facts, sources, value, dtype, now)[:_MAX_FINDINGS],
        # ponytail: address blocks are never rendered, so skip their details
        details=[] if dtype == "mail" else detail_groups(facts, dtype),
        connectors=connector_lines(sources, facts),
        vt_link=facts.vt_link, derived_from=row.get("derived_from"),
        escalation_note=row.get("escalation_note") or "",
        screenshot_url=row.get("screenshot_url"),
    )


def _health_text(health: dict | None) -> str | None:
    if not health or not (health.get("failed") or health.get("pending")):
        return None
    parts = []
    if health.get("failed"):
        names = ", ".join(sorted({f["analyzer"] for f in health.get("failures", [])}))
        parts.append(f"{health['failed']} of {health['total']} analyzers failed"
                     + (f" ({names})" if names else "") + ": the verdict has lower confidence")
    if health.get("pending"):
        parts.append(f"{health['pending']} analyzer(s) still running")
    return "; ".join(parts)


def _sort_key(b):
    return (BAND_RANK.get(b.band, len(BAND_RANK)), b.value)


def _target_label(r) -> str:
    if r.file_id:
        return str(r.file.file_path.name or r.file.linked_hash.value)
    return "mail body" if r.mail_body_id else "headers"


def _case_connectors(reports) -> list[ConnectorLine]:
    from api.utils.observable_report import _source_rows
    from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name

    ai = ai_analyzer_name()
    own = [r for r in reports
           if (r.mail_header_id or r.mail_body_id or r.file_id) and r.analyzer.name != ai]
    # one source per (analyzer, target): _source_rows skips repeated analyzers, so call it per report
    per = Counter(r.analyzer_id for r in own)
    sources = []
    for r in own:
        src = _source_rows([r], full=False)[0][0]
        if per[r.analyzer_id] > 1:
            src["name"] = f"{src['name']} ({_target_label(r)})"
        sources.append(src)
    return connector_lines(sources, vt_facts(None, None, "file", ""))


_AI_ICON = {"Dangerous": "🔴", "Unwanted": "🟠", "Safe": "🟢"}


def ai_connector_line(payload: dict) -> ConnectorLine:
    result, tier = str(payload.get("result") or ""), str(payload.get("tier") or "")
    label = f"{result}, {tier.title()} confidence" if tier else result
    return ConnectorLine(_AI_ICON.get(result, "⚪"), "AI model", label, result, 0)


def build_case_report(case, request, *, now: datetime | None = None) -> CaseReport:
    from api.utils.analyzer_reports import reports_for_case
    from api.utils.observable_report import (
        assemble_file_observable, assemble_mail_observables, assemble_observables,
    )
    from api.views.investigations import _dedup_analyzer_reports
    from score_process.scoring.classification import derive_threat_classification
    from score_process.scoring.health import analysis_health

    now = now or datetime.now(dt_tz.utc)
    reports = _dedup_analyzer_reports(reports_for_case(case, defer_full=True))
    fom = case.fileOrMail if case.fileOrMail_id else None
    expl = case.verdict_explanation or {}
    why = [t for t in (expl.get("analyst_paragraph"), expl.get("confidence_reading")) if t]
    if not why:
        why = list(case.verdict_rationale or []) or ([case.inconclusive_reason] if case.inconclusive_reason else [])

    rep = CaseReport(
        case_id=case.pk, kind="none", band=str(case.results),
        confidence=f"{round(case.final_confidence)}%" if case.final_confidence else None,
        threat=derive_threat_classification(case, reports),
        health=_health_text(analysis_health(reports)),
        lead=expl.get("reporter_paragraph") or case.inconclusive_reason or None,
        reporter=case.reporter.username,
        created=iso_utc(case.creation_date), generated=iso_utc(now),
        description=case.description or "", reporter_context=case.reporter_context or "",
        why=why,
    )

    if fom and fom.mail_id:
        rep.kind = "mail"
        rep.case_connectors = _case_connectors(reports)
        from api.utils.ai_assessment import ai_assessment_for

        ai = ai_assessment_for(case, request)  # None while the connector is off; redacted per viewer
        if ai:
            rep.ai = {**ai, "analysed_at": iso_utc(ai.get("analysed_at"))}
            rep.case_connectors.append(ai_connector_line(ai))
            rep.case_connectors.sort(key=lambda l: (_VERDICT_RANK[l.icon], l.tier, l.name.lower()))
        blocks = sorted((build_block(r, now=now) for r in assemble_mail_observables(case, fom.mail, full=True)), key=_sort_key)
        rep.rows = [IndicatorRow(b.type, b.value, b.band, b.findings[0] if b.findings else None) for b in blocks]
        eligible = [b for b in blocks if b.band in _FLAGGED and b.type != "mail"]
        rep.blocks, rep.more = eligible[:BLOCK_CAP], max(0, len(eligible) - BLOCK_CAP)
    elif fom and fom.file_id:
        rep.kind = "file"
        block = build_block(assemble_file_observable(case, fom.file, full=True), now=now)
        block.band, block.confidence, block.why = str(case.results), round(case.final_confidence), []
        rep.case_analysis = block
    elif case.observable_group_id:
        rep.kind = "group"
        blocks = sorted((build_block(r, now=now) for r in assemble_observables(case, full=True)), key=_sort_key)
        rep.blocks, rep.more = blocks[:BLOCK_CAP], max(0, len(blocks) - BLOCK_CAP)
        if len(blocks) > BLOCK_CAP:
            rep.rows = [IndicatorRow(b.type, b.value, b.band, b.findings[0] if b.findings else None) for b in blocks]
    return rep
