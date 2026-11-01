"""Turn a case's AiAssessment into the plain dict the case views render.

No numeric confidence leaves this module: people see the class, the tier and,
on tier ``low``, the runner-up class.
"""

from api.permissions.submissions import has_elevated_view, submission_queryset
from case_handler.models import Case

_AXIS = {"SAFE", "DANGEROUS"}  # the only classes that can disagree
_TIERS = {"high", "medium", "low"}
_AI_RULE = "ai-classifier-decisive"
_SIMILAR_KEYS = ("case_id", "similarity", "label", "provenance")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _display(name: str) -> str:
    """Stored classes are uppercase (AiAssessment.Result); people read title case."""
    return str(name).title()


def _runner_up(assessment):
    if assessment.tier != "low":
        return None
    probabilities = assessment.probabilities if isinstance(assessment.probabilities, dict) else {}
    usable = [(k, v) for k, v in probabilities.items() if _is_number(v)]
    ranked = sorted(usable, key=lambda kv: kv[1], reverse=True)
    others = [name for name, _ in ranked if name.upper() != assessment.result.upper()]
    return {"result": _display(others[0])} if others else None


def _visible_similar_cases(assessment, user):
    entries = [
        {key: e.get(key) for key in _SIMILAR_KEYS}
        for e in assessment.similar_cases
        if isinstance(e, dict) and _is_int(e.get("case_id"))
    ]
    if not entries:
        return []
    ids = {e["case_id"] for e in entries}
    allowed = set(
        submission_queryset(Case.objects.filter(pk__in=ids), user).values_list("pk", flat=True)
    )
    return [e for e in entries if e["case_id"] in allowed]


def _campaign(case):
    membership = getattr(case, "campaign_membership", None)
    if membership is None:
        return None
    campaign = membership.campaign
    return {"ref": campaign.ref, "size": campaign.members.count()}  # served from a prefetch when present


def cross_check(case, assessment) -> dict:
    """Facts from the verdict explanation and the list hit, and whether the AI class
    sits on the other side of the Safe/Dangerous axis from the case verdict band."""
    explanation = case.verdict_explanation if isinstance(case.verdict_explanation, dict) else {}
    rule = explanation.get("decisive_rule")
    ai_decided = rule == _AI_RULE  # the AI set the band: agreement or conflict would be circular
    facts = []
    if ai_decided:
        facts.append({"kind": "rule", "text": "No independent evidence beyond the AI"})
    elif rule:
        facts.append({"kind": "rule", "text": f"Decisive rule: {rule}"})
    sources = explanation.get("sources")
    for source in sources if isinstance(sources, list) else []:
        if isinstance(source, dict) and source.get("counted"):
            facts.append(
                {"kind": "source", "text": f"{source.get('name')} reported {source.get('verdict')}."}
            )
    if case.is_denylisted or case.is_allowlisted:
        which = "deny list" if case.is_denylisted else "allow list"
        reason = f": {case.list_reason}" if case.list_reason else ""
        facts.append({"kind": "list", "text": f"The case matched the {which}{reason}."})
    ai = assessment.result.upper()
    # Without an explanation (or a band in it) the case's current verdict stands in, so an
    # analyst override is still compared.
    band = str(explanation.get("band") or case.results or "").upper()
    disagrees = not ai_decided and ai in _AXIS and band in _AXIS and ai != band
    return {"facts": facts, "disagrees": disagrees}


def present_assessment(case, user, elevated: bool | None = None) -> dict | None:
    if elevated is None:
        elevated = has_elevated_view(user, case)
    assessment = getattr(case, "ai_assessment", None)
    if assessment is None or not assessment.model_version:
        return None
    return {
        "result": _display(assessment.result),
        "sub_class": assessment.sub_class,
        "tier": assessment.tier if assessment.tier in _TIERS else "",
        "runner_up": _runner_up(assessment),
        "model_version": assessment.model_version,
        "analysed_at": assessment.updated_at,
        "reads": "body text only, not headers or attachments",  # the inference input is the .txt only
        "similar_cases": _visible_similar_cases(assessment, user),
        "campaign": _campaign(case),
        # The rule and list reason are analyst material, as `raw` is.
        "cross_check": cross_check(case, assessment) if elevated else None,
    }
