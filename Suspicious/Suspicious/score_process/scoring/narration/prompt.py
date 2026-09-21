"""Assembles the full narration prompt: fixed verdict facts + full analyzer
reports + generation instructions. Pure — no ORM, no Django models."""
from __future__ import annotations

import json

from score_process.scoring.narration.verdict_lock import render_fixed_facts

_INSTRUCTIONS = (
    "You are writing a plain-language incident report for a non-technical "
    "reader. Use the fixed case facts above exactly as given — do not "
    "restate them differently, soften them, or draw your own conclusion "
    "about whether this case is safe or dangerous. Explain what the "
    "analyzer findings below mean in plain language, and how they support "
    "the given verdict. Never mention the decisive rule's internal name "
    "(e.g. \"weighted-malicious-share\", \"group-worst-of\") — instead "
    "describe in plain words why that pattern of findings led to this "
    "verdict. Write the report as a finished document, not a conversation: "
    "do not end with an offer to answer further questions or any other "
    "chat-style closing."
)


def build_prompt(verdict: dict, analyzer_reports: list) -> str:
    facts = render_fixed_facts(verdict)

    if analyzer_reports:
        reports_block = "\n\n".join(
            f"### {report.get('analyzer', 'unknown analyzer')}\n"
            f"{json.dumps(report.get('report_full', {}), indent=2)}"
            for report in analyzer_reports
        )
    else:
        reports_block = "(no analyzer reports available)"

    return (
        f"{facts}\n"
        f"ANALYZER REPORTS:\n{reports_block}\n\n"
        f"INSTRUCTIONS:\n{_INSTRUCTIONS}\n"
    )
