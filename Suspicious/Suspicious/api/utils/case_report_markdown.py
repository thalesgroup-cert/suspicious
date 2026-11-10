"""Markdown version of the case report: verdict, why, and per-indicator evidence.

Every value that comes from outside (indicators, analyzer evidence, reporter text)
is escaped so a viewer cannot turn it into a link, a heading or a table break.
Screenshots and raw analyzer output stay in the HTML report."""
from __future__ import annotations

import re

from api.utils.case_report_model import CaseReport, IndicatorBlock
from api.utils.report_facts import LEGEND, band_icon

# Always special in running text and table cells. Parentheses are left alone: with
# "[" and "]" escaped, a link or image can never form.
_ALWAYS = re.compile(r"([\\`*\[\]<>|~])")
# An underscore only formats at a word edge ("Abuse_Finder_3_0" stays readable).
_EDGE_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
# Block markers if they begin the line: heading, quote, list, ordered list.
_LEADING_MARKER = re.compile(r"^(\s*)([#>+=-])")
_LEADING_ORDERED = re.compile(r"^(\s*\d+)([.)])")


def _text(value) -> str:
    """Escape for use in running text or a table cell; one line."""
    one_line = " ".join(str(value if value is not None else "").split())
    escaped = _ALWAYS.sub(r"\\\1", one_line)
    escaped = _EDGE_UNDERSCORE.sub(r"\\_", escaped)
    escaped = _LEADING_MARKER.sub(r"\1\\\2", escaped)
    return _LEADING_ORDERED.sub(r"\1\\\2", escaped)


def _code(value) -> str:
    """Inline code span that survives backticks in the value."""
    one_line = " ".join(str(value if value is not None else "").split())
    longest = max((len(run) for run in re.findall(r"`+", one_line)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if one_line.startswith("`") or one_line.endswith("`") else ""
    return f"{fence}{pad}{one_line}{pad}{fence}"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(" --- " for _ in header) + "|"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return out


def _verdict(band, confidence) -> str:
    text = f"{band_icon(band)} {_text(band or 'Inconclusive')}"
    return text + (f" · confidence {_text(confidence)}%" if confidence is not None else "")


def _ai_section(ai: dict) -> list[str]:
    head = _text(ai.get("result"))
    if ai.get("sub_class"):
        head += f" ({_text(ai['sub_class'])})"
    if ai.get("tier"):
        head += f" · {_text(str(ai['tier']).title())} confidence"
    ru = ai.get("runner_up")
    if isinstance(ru, dict) and ru.get("result"):
        head += f" · runner-up: {_text(ru['result'])}"
    out = ["## AI model assessment", "", head,
           f"Model {_text(ai.get('model_version'))} · analysed {_text(ai.get('analysed_at'))}",
           f"Reads: {_text(ai.get('reads'))}"]
    camp = ai.get("campaign")
    if isinstance(camp, dict):
        line = f"Campaign {_text(camp.get('ref'))} · {_text(camp.get('size'))} mails"
        labels = camp.get("labels")
        if isinstance(labels, dict) and labels:
            line += " · labels " + ", ".join(f"{_text(k)} {_text(v)}" for k, v in labels.items())
        out.append(line)
    for sc in ai.get("similar_cases") or []:
        if isinstance(sc, dict):
            out.append(f"Similar case #{_text(sc.get('case_id'))}: {_text(sc.get('label'))}")
    cc = ai.get("cross_check")
    if isinstance(cc, dict):
        out += [f"- {_text(f.get('text'))}" for f in cc.get("facts") or [] if isinstance(f, dict)]
        if cc.get("disagrees"):
            out.append("AI and evidence disagree")
    return out + [""]


def _block(b: IndicatorBlock, heading: str) -> list[str]:
    out = [heading, "", f"Verdict: {_verdict(b.band, b.confidence)}", ""]
    if b.why:
        out += ["**Why this verdict**", ""] + [f"- {_text(w)}" for w in b.why] + [""]
    if b.derived_from:
        out += [f"Found in {_code(b.derived_from.get('value'))} by {_text(b.derived_from.get('via_analyzer'))}.", ""]
    if b.escalation_note:
        out += [_text(b.escalation_note), ""]
    if b.findings:
        out += ["**Key findings**", ""] + [f"- {_text(f)}" for f in b.findings] + [""]
    groups = [g for g in b.details if g.rows]
    if groups:
        out += ["**Details**", ""]
        for g in groups:
            out += [f"*{_text(g.title)}*", ""] + [f"- {_text(k)}: {_text(v)}" for k, v in g.rows] + [""]
    if b.vt_link:
        out += [f"VirusTotal: {_text(b.vt_link)}", ""]
    if b.connectors:
        out += ["**Connectors**", ""] + [f"- {c.icon} {_text(c.name)}: {_text(c.label)}" for c in b.connectors] + [""]
    return out


def build_markdown_report(report: CaseReport) -> str:
    r = report
    out = [f"# Case #{r.case_id}: {_text(r.band)}", "",
           f"**Verdict:** {band_icon(r.band)} {_text(r.band)}"
           + (f" · confidence {_text(r.confidence)}" if r.confidence else "")]
    if r.threat:
        out.append(f"**Threat:** {_text(r.threat.get('label'))} ({_text(r.threat.get('category'))})")
    if r.health:
        out.append(f"**Analysis:** {_text(r.health)}.")
    out.append("")
    if r.lead:
        out += [_text(r.lead), ""]
    meta = [f"Reporter: {_text(r.reporter)}"]
    if r.created:
        meta.append(f"Case created: {_text(r.created)}")
    meta.append(f"Report generated: {_text(r.generated)}")
    out += ["  \n".join(meta), ""]
    if r.description:
        out += ["## Description", "", _text(r.description), ""]
    if r.reporter_context:
        out += ["## Reporter context", "", _text(r.reporter_context), ""]
    if r.why:
        out += ["## Why this verdict", ""] + [f"- {_text(w)}" for w in r.why] + [""]
    if r.ai:
        out += _ai_section(r.ai)
    if r.case_connectors:
        out += ["## Case analyzers", "", "**Legend** " + LEGEND, ""]
        out += [f"- {c.icon} {_text(c.name)}: {_text(c.label)}" for c in r.case_connectors] + [""]
    if r.case_analysis:
        out += _block(r.case_analysis, "## Case analysis")
    out += ["## Indicators", ""]
    if r.kind == "none" or not (r.rows or r.blocks):
        out += ["No indicator observables on this case.", ""]
    else:
        out += ["**Legend** " + LEGEND, ""]
        if r.rows:
            out += _table(["Value", "Type", "Verdict", "Top finding"],
                          [[_code(x.value).replace("|", "\\|"), _text(x.type.upper()), _verdict(x.band, None), _text(x.top_finding)]
                           for x in r.rows]) + [""]
        for b in r.blocks:
            out += _block(b, f"### {_text(b.type.upper())} · {_code(b.value)}")
        if r.more:
            out += [f"+{r.more} more flagged indicators are listed in the table only.", ""]
    out += ["---", "Generated by Suspicious. Screenshots are in the HTML report.", ""]
    return "\n".join(out)
