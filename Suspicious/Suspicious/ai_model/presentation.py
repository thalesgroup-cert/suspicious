"""Turn a case's AiAssessment into the plain dict the case views render.

No numeric confidence leaves this module: people see the class, the tier and,
on tier ``low``, the runner-up class.
"""

from api.permissions.submissions import submission_queryset
from case_handler.models import Case

_AXIS = {"SAFE", "DANGEROUS"}  # the only classes that can disagree


def _display(name: str) -> str:
    """Stored classes are uppercase (AiAssessment.Result); people read title case."""
    return str(name).title()


def _runner_up(assessment):
    if assessment.tier != "low":
        return None
    ranked = sorted(assessment.probabilities.items(), key=lambda kv: kv[1], reverse=True)
    others = [name for name, _ in ranked if name.upper() != assessment.result.upper()]
    return {"result": _display(others[0])} if others else None


def _visible_similar_cases(assessment, user):
    entries = [e for e in assessment.similar_cases if isinstance(e, dict)]
    ids = {e.get("case_id") for e in entries}
    if not ids:
        return []
    allowed = set(
        submission_queryset(Case.objects.filter(pk__in=ids), user).values_list("pk", flat=True)
    )
    return [e for e in entries if e.get("case_id") in allowed]


def _campaign(case):
    membership = getattr(case, "campaign_membership", None)
    if membership is None:
        return None
    campaign = membership.campaign
    return {"ref": campaign.ref, "size": len(campaign.members.all())}  # uses a prefetch when present


def cross_check(case, assessment) -> dict:
    """Facts from the verdict explanation and the list hit, and whether the AI class
    sits on the other side of the Safe/Dangerous axis from the case band."""
    explanation = case.verdict_explanation or {}
    facts = []
    if explanation.get("decisive_rule"):
        facts.append({"kind": "rule", "text": f"Decisive rule: {explanation['decisive_rule']}"})
    for source in explanation.get("sources") or []:
        if source.get("counted"):
            facts.append(
                {"kind": "source", "text": f"{source.get('name')} reported {source.get('verdict')}."}
            )
    if case.is_denylisted or case.is_allowlisted:
        which = "deny list" if case.is_denylisted else "allow list"
        reason = f": {case.list_reason}" if case.list_reason else ""
        facts.append({"kind": "list", "text": f"The case matched the {which}{reason}."})
    ai = assessment.result.upper()
    band = str(explanation.get("band") or "").upper()
    disagrees = ai in _AXIS and band in _AXIS and ai != band
    return {"facts": facts, "disagrees": disagrees}


def present_assessment(case, user) -> dict | None:
    assessment = getattr(case, "ai_assessment", None)
    if assessment is None:
        return None
    return {
        "result": _display(assessment.result),
        "sub_class": assessment.sub_class,
        "tier": assessment.tier,
        "runner_up": _runner_up(assessment),
        "model_version": assessment.model_version,
        "analysed_at": assessment.updated_at,
        "reads": "body only",
        "similar_cases": _visible_similar_cases(assessment, user),
        "campaign": _campaign(case),
        "cross_check": cross_check(case, assessment),
    }
