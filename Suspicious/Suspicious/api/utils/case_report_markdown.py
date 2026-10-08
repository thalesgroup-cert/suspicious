"""Markdown version of the case report: verdict, why, and per-indicator evidence.

Every value that comes from outside (indicators, analyzer evidence, reporter text)
is escaped so a viewer cannot turn it into a link, a heading or a table break.
Screenshots and raw analyzer output stay in the HTML report."""
from __future__ import annotations

import re

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


def _health_line(health: dict | None) -> str | None:
    if not health or not (health.get("failed") or health.get("pending")):
        return None
    parts = []
    if health.get("failed"):
        names = ", ".join(sorted({f["analyzer"] for f in health.get("failures", [])}))
        parts.append(
            f"{health['failed']} of {health['total']} analyzers failed"
            + (f" ({_text(names)})" if names else "")
            + ": the verdict has lower confidence"
        )
    if health.get("pending"):
        parts.append(f"{health['pending']} analyzer(s) still running")
    return "**Analysis:** " + "; ".join(parts) + "."


def build_markdown_report(case, observables, sources, threat, health, generated_at) -> str:
    result = str(case.results)
    explanation = case.verdict_explanation or {}
    lines = [f"# Case #{case.id}: {_text(result)}", ""]

    stats = [f"**Verdict:** {_text(result)}"]
    if case.final_score or case.final_confidence:
        if not observables:
            stats.append(f"Score {case.final_score}")
        stats.append(f"Confidence {case.final_confidence}")
    lines.append(" · ".join(stats))
    if threat:
        lines.append(f"**Threat:** {_text(threat['label'])} ({_text(threat['category'])})")
    health_line = _health_line(health)
    if health_line:
        lines.append(health_line)
    lines.append("")

    lead = explanation.get("reporter_paragraph") or case.inconclusive_reason
    if lead:
        lines += [_text(lead), ""]

    meta = [f"Reporter: {_text(case.reporter.username)}"]
    if case.creation_date:
        meta.append(f"Case created: {case.creation_date:%Y-%m-%d %H:%M} UTC")
    meta.append(f"Report generated: {generated_at:%Y-%m-%d %H:%M} UTC")
    lines += ["  \n".join(meta), ""]

    if case.description:
        lines += ["## Description", "", _text(case.description), ""]
    if case.reporter_context:
        lines += ["## Reporter context", "", _text(case.reporter_context), ""]

    if explanation:
        lines += ["## Why this verdict", ""]
        if explanation.get("analyst_paragraph"):
            lines += [_text(explanation["analyst_paragraph"]), ""]
        if explanation.get("confidence_reading"):
            lines += [f"_{_text(explanation['confidence_reading'])}_", ""]
        if sources:
            lines += _table(
                ["Source", "Tier", "Verdict", "Note"],
                [[_text(s.get("name")), f"T{_text(s.get('tier'))}", _text(s.get("verdict")),
                  _text(s.get("note")) + (f" (x{s['n']})" if s.get("n", 1) > 1 else "")] for s in sources],
            ) + [""]
    elif case.verdict_rationale:
        lines += ["## Why this verdict", ""] + [f"- {_text(line)}" for line in case.verdict_rationale] + [""]

    lines += ["## Indicators", ""]
    if not observables:
        lines += ["No indicator observables on this case.", ""]
    for o in observables:
        lines += [f"### {_code(o['value'])} ({_text(o['type'])})", ""]
        verdict = o.get("verdict")
        if verdict:
            lines.append(f"**Verdict:** {_text(verdict['band'])} · Confidence {_text(verdict['confidence'])}")
            lines += [f"- {_text(line)}" for line in verdict.get("rationale") or []]
        if o.get("derived_from"):
            lines.append(f"Found in {_code(o['derived_from']['value'])} by {_text(o['derived_from']['via_analyzer'])}.")
        if o.get("escalation_note"):
            lines.append(_text(o["escalation_note"]))
        if o.get("sources"):
            lines += [""] + _table(
                ["Source", "Tier", "Verdict", "Evidence"],
                [[_text(s["name"]) + (" (failed)" if s.get("failed") else ""), f"T{_text(s['tier'])}",
                  _text(s["verdict"]), _text(s.get("evidence"))] for s in o["sources"]],
            )
        lines.append("")

    lines += ["---", "Generated by Suspicious. Screenshots and raw analyzer output are in the HTML report.", ""]
    return "\n".join(lines)
