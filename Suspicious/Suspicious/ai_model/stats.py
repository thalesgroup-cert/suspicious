"""Daily per-version counters, label purity and warnings (Ruling F10). Plain ORM reads of live data."""
from collections import defaultdict
from datetime import timedelta

from django.db.models import Min
from django.utils import timezone

from .models import AiAssessment, LabelRecord, ModelVersion, ModelVersionStats

PURITY_DAYS = 30
MIN_LABELLED = 10
MIN_PURITY = 0.8
AGE_WARNING_DAYS = 60


def _versions(case_ids):
    return dict(AiAssessment.objects.filter(case_id__in=set(case_ids)).values_list("case_id", "model_version"))


def recompute(days=3, now=None):
    """Rebuild the rows of the last `days` days (today included); idempotent."""
    from case_handler.models import CampaignMember
    from connectors.models import ConnectorDelivery

    today = (now or timezone.now()).date()
    first = today - timedelta(days=days - 1)
    start = timezone.make_aware(timezone.datetime.combine(first, timezone.datetime.min.time()))
    counts = defaultdict(lambda: defaultdict(int))  # (version_id, day) -> counter

    for a in AiAssessment.objects.filter(created_at__gte=start).values("model_version", "result", "created_at"):
        c = counts[(a["model_version"], timezone.localtime(a["created_at"]).date())]
        c["scored"] += 1
        c["dangerous"] += a["result"] == AiAssessment.Result.DANGEROUS

    # A campaign's first member created it; every later member joined it.
    firsts = dict(CampaignMember.objects.values("campaign_id").annotate(m=Min("id")).values_list("campaign_id", "m"))
    members = list(CampaignMember.objects.filter(joined_at__gte=start).values("id", "campaign_id", "case_id", "joined_at"))
    deliveries = list(ConnectorDelivery.objects.filter(
        created_at__gte=start, status=ConnectorDelivery.STATUS_SUCCESS, case_id__isnull=False,
    ).filter(connector="ai_model", event="case_finalised").values("case_id", "created_at"))
    alerts = list(ConnectorDelivery.objects.filter(
        created_at__gte=start, status=ConnectorDelivery.STATUS_SUCCESS, case_id__isnull=False,
        connector="thehive", event="campaign_updated").values("case_id", "created_at"))
    owner = _versions([m["case_id"] for m in members] + [d["case_id"] for d in deliveries + alerts])

    for m in members:
        if m["case_id"] in owner:
            key = "created" if firsts[m["campaign_id"]] == m["id"] else "joined"
            counts[(owner[m["case_id"]], timezone.localtime(m["joined_at"]).date())][key] += 1
    # ponytail: campaign_checks = successful ai_model case_finalised deliveries (the hook queues the
    # detection); a delivery is a queued check, not proof the task finished.
    for rows, key in ((deliveries, "campaign_checks"), (alerts, "alerts")):
        for r in rows:
            if r["case_id"] in owner:
                counts[(owner[r["case_id"]], timezone.localtime(r["created_at"]).date())][key] += 1

    by_id = {v.version_id: v for v in ModelVersion.objects.filter(version_id__in={k[0] for k in counts})}
    ModelVersionStats.objects.filter(day__gte=first).delete()
    ModelVersionStats.objects.bulk_create(
        ModelVersionStats(version=by_id[vid], day=day, **c)
        for (vid, day), c in counts.items() if vid in by_id and day >= first
    )


def purity(version, now=None):
    """Dangerous share among the version's campaign members of the last 30 days that carry an
    active label. {"labelled", "dangerous", "purity" (None when nothing is labelled), "warning"}."""
    from case_handler.models import CampaignMember

    since = (now or timezone.now()) - timedelta(days=PURITY_DAYS)
    cases = CampaignMember.objects.filter(
        joined_at__gte=since, case__ai_assessment__model_version=version.version_id
    ).values_list("case_id", flat=True)
    labels = {}
    for case_id, klass in LabelRecord.objects.filter(
        case_id__in=list(cases), status=LabelRecord.Status.ACTIVE
    ).order_by("observed_at", "id").values_list("case_id", "label_class"):
        labels[case_id] = klass  # latest active label wins
    n, bad = len(labels), sum(k == LabelRecord.LabelClass.DANGEROUS for k in labels.values())
    p = bad / n if n else None
    return {"labelled": n, "dangerous": bad, "purity": p,
            "warning": n >= MIN_LABELLED and p < MIN_PURITY}


def age_warning(version, now=None):
    """True when the version was created (registered) more than 60 days ago."""
    return (now or timezone.now()) - version.created_at > timedelta(days=AGE_WARNING_DAYS)
