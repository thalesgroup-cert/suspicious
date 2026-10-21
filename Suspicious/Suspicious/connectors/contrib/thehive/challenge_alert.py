"""The TheHive alert for a challenged mail case.

Same content and upload path as a campaign alert (observables, original mail and
attachments), with the challenge itself on top.
"""
from __future__ import annotations

import logging

import requests

from connectors.contrib.thehive.campaign_alert import (
    PAP_AMBER,
    TLP_AMBER,
    CampaignContent,
    MemberMaterial,
    _build_files,
    attachment_lines,
    build_observables,
    defang_urls_in,
    preview_parts,
    indicator_lines,
    severity_for,
)

logger = logging.getLogger(__name__)

ALERT_TYPE = "user_challenge"


def _description(case, member: MemberMaterial, challenger: dict, rows, ui_base: str) -> str:
    name = " ".join(p for p in (challenger.get("firstname"), challenger.get("lastname")) if p) or "The reporter"
    reason = (case.challenge_reason or "No reason provided.").strip().replace("\n", "\n> ")
    lines = [
        f"# Reporter disputes **{case.results or 'N/A'}** and proposes **{case.challenge_proposed_result or 'no verdict'}**",
        "", f"> {reason}", "",
        "| | |", "|---|---|",
        f"| Reporter | {name} ({challenger.get('email') or 'N/A'}) |",
        f"| Case | [#{case.id}]({ui_base}/investigation?open={case.id}) |",
        f"| Mail subject | {member.info.subject or 'N/A'} |",
        f"| Verdict | {case.results or 'N/A'} (score {case.score}, confidence {case.confidence}) |",
        f"| AI suggestion | {case.category_ai or 'N/A'} / {case.results_ai or 'N/A'} "
        f"(score {case.score_ai}, confidence {case.confidence_ai}) |",
        f"| Email authentication | {', '.join(member.iocs.auth_failures) or 'no failure recorded'} |",
    ]
    if case.verdict_rationale:
        lines += ["", "## Why this verdict"] + [f"- {r}" for r in case.verdict_rationale]
    lines += indicator_lines(member.iocs) + attachment_lines(rows, count=False)
    lines += ["", "The mail and its attachments are file observables; the rendered mail is in the Attachments tab. "
              "Every observable is in the Observables tab."]
    example = defang_urls_in((member.material.text or member.material.html or "")[:1500]).replace("```", "'''")
    if example:
        lines += ["", "## Example mail body", "```", example, "```"]
    return "\n".join(lines)


def build_challenge_content(case, member: MemberMaterial, challenger: dict, *,
                            ref: str, ui_base: str) -> CampaignContent:
    files, rows = _build_files([member])
    return CampaignContent(
        title=f"Challenge: Case #{case.id} - {member.info.subject or 'No Subject'}",
        description=_description(case, member, challenger, rows, ui_base),
        severity=severity_for([str(case.results)], 1),
        tlp=TLP_AMBER, pap=PAP_AMBER,
        tags=["challenge", "mail", "suspicious", f"suspicious:case:{case.id}"],
        source_ref=ref,
        observables=build_observables(member.iocs),
        files=files,
        attachments=preview_parts([member]),
        alert_type=ALERT_TYPE,
    )


def send_challenge_alert(client, case, member: MemberMaterial, challenger: dict, *,
                         ref: str, ui_base: str) -> dict:
    """Files TheHive should analyse (the mail, its attachments) go up as file
    observables; the Attachments tab gets the rendered mail as evidence."""
    content = build_challenge_content(case, member, challenger, ref=ref, ui_base=ui_base)
    alert = client.create_alert(content)
    try:
        client.add_attachments(alert["_id"], content.attachments)
    except requests.RequestException as exc:
        logger.warning("Challenge alert %s: could not attach the mail preview: %s", alert.get("_id"), exc)
    return alert
