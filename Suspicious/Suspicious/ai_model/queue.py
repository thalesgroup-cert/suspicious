"""The review queue (ruling G9): two bounded lists of ids and classes, never mail content."""
from datetime import timedelta

from django.utils import timezone

from ai_model.models import AiAssessment, LabelRecord
from ai_model.presentation import cross_check, members_disagree

AXIS = ("SAFE", "DANGEROUS")


def disagreements(since_days=30, cap=200) -> list[dict]:
    """Finalised mail cases whose AI class is on the other side of the Safe/Dangerous axis from the
    verdict and where the AI did not set the band (presentation.cross_check), newest first."""
    since = timezone.now() - timedelta(days=since_days)
    rows = (AiAssessment.objects.filter(case__finalized_at__gte=since, result__in=AXIS,
                                        case__fileOrMail__mail__isnull=False)
            .select_related("case").order_by("-case__finalized_at", "-pk"))
    out = []
    for a in rows.iterator():
        if cross_check(a.case, a)["disagrees"]:
            out.append({"case_id": a.case_id, "verdict": a.case.results, "ai_class": a.result.title(),
                        "date": a.case.finalized_at})
            if len(out) >= cap:
                break
    return out


def campaign_conflicts(cap=200) -> list[dict]:
    """Campaigns whose active folder-labelled members include both Dangerous and Safe, newest first."""
    pairs = (LabelRecord.objects.filter(
        source=LabelRecord.Source.IMAP_FOLDER, trust=LabelRecord.Trust.FOLDER, status=LabelRecord.Status.ACTIVE,
        label_class__in=("Dangerous", "Safe"), case__campaign_membership__isnull=False)
        .order_by().values_list("case__campaign_membership__campaign__ref",
                                "case__campaign_membership__campaign__updated_at", "label_class").distinct())
    seen: dict[str, dict] = {}
    for ref, updated, label_class in pairs:
        seen.setdefault(ref, {"updated": updated, "labels": {}})["labels"][label_class] = 1
    rows = sorted((r, v) for r, v in seen.items() if members_disagree(v["labels"]))
    rows.sort(key=lambda rv: rv[1]["updated"], reverse=True)
    return [{"campaign_ref": r, "classes": ["Dangerous", "Safe"], "date": v["updated"]} for r, v in rows[:cap]]
