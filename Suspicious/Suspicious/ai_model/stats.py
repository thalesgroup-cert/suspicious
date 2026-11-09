"""Daily per-version counters, label purity and warnings (Ruling F10). Plain ORM reads of live data."""
from collections import defaultdict
from datetime import timedelta

from django.db import transaction
from django.db.models import F, Min
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

    today = timezone.localdate(now)
    first = today - timedelta(days=days - 1)
    start = timezone.make_aware(timezone.datetime.combine(first, timezone.datetime.min.time()))
    counts = defaultdict(lambda: defaultdict(int))  # (version_id, day) -> counter

    for a in AiAssessment.objects.filter(created_at__gte=start).values("model_version", "result", "created_at"):
        c = counts[(a["model_version"], timezone.localtime(a["created_at"]).date())]
        c["scored"] += 1
        c["dangerous"] += a["result"] == AiAssessment.Result.DANGEROUS

    # A campaign's first member created it; every later member joined it.
    members = list(CampaignMember.objects.filter(joined_at__gte=start).values("id", "campaign_id", "case_id", "joined_at"))
    firsts = dict(CampaignMember.objects.filter(campaign_id__in={m["campaign_id"] for m in members})
                  .values("campaign_id").annotate(m=Min("id")).values_list("campaign_id", "m"))
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
    # detection); a delivery is a queued check, not proof it ran: the task returns without
    # detecting when the mail text is unreadable, so this can overcount.
    for rows, key in ((deliveries, "campaign_checks"), (alerts, "alerts")):
        for r in rows:
            if r["case_id"] in owner:
                counts[(owner[r["case_id"]], timezone.localtime(r["created_at"]).date())][key] += 1

    by_id = {v.version_id: v for v in ModelVersion.objects.filter(version_id__in={k[0] for k in counts})}
    with transaction.atomic():
        ModelVersionStats.objects.filter(day__gte=first).delete()
        ModelVersionStats.objects.bulk_create(
            ModelVersionStats(version=by_id[vid], day=day, **c)
            for (vid, day), c in counts.items() if vid in by_id and day >= first
        )


def purity_many(versions, now=None):
    """{version_id: purity dict} for several versions in two queries. Purity: Dangerous share among
    the version's campaign members of the last 30 days that carry an active label (latest wins).
    {"labelled", "dangerous", "purity" (None when nothing is labelled), "warning"}."""
    from case_handler.models import CampaignMember

    since = (now or timezone.now()) - timedelta(days=PURITY_DAYS)
    ids = [v.version_id for v in versions]
    owner = dict(CampaignMember.objects.filter(joined_at__gte=since, case__ai_assessment__model_version__in=ids)
                 .values_list("case_id", "case__ai_assessment__model_version"))
    labels = {}
    for case_id, klass in LabelRecord.objects.filter(
        case_id__in=list(owner), status=LabelRecord.Status.ACTIVE
    ).order_by("observed_at", "id").values_list("case_id", "label_class"):
        labels[case_id] = klass  # latest active label wins
    out = {}
    for vid in ids:
        mine = [k for c, k in labels.items() if owner[c] == vid]
        n, bad = len(mine), sum(k == LabelRecord.LabelClass.DANGEROUS for k in mine)
        p = bad / n if n else None
        out[vid] = {"labelled": n, "dangerous": bad, "purity": p, "warning": n >= MIN_LABELLED and p < MIN_PURITY}
    return out


def purity(version, now=None):
    return purity_many([version], now)[version.version_id]


def totals(versions):
    """{version_id: summed counters} over all stored days, one grouped query."""
    from django.db.models import Sum

    rows = ModelVersionStats.objects.filter(version__in=versions).values("version__version_id").annotate(
        scored=Sum("scored"), dangerous=Sum("dangerous"), checks=Sum("campaign_checks"),
        created_=Sum("created"), joined=Sum("joined"), alerts=Sum("alerts"))
    by = {r["version__version_id"]: r for r in rows}
    keys = ("scored", "dangerous", "checks", "joined", "alerts")
    return {v.version_id: {**{k: by.get(v.version_id, {}).get(k) or 0 for k in keys},
                           "created": by.get(v.version_id, {}).get("created_") or 0} for v in versions}


def agreement(version):
    """Live shadow results with a would-be verdict: how often the shadow agrees with the live side.
    class: shadow class vs the case's live AI class; verdict: live case result vs would-be result.
    Grouped counts, nothing loaded row by row."""
    from django.db.models import Count

    from .models import ShadowResult

    live = ShadowResult.objects.filter(version=version, origin=ShadowResult.Origin.LIVE).exclude(would_be_result="")

    def tally(pairs):
        return {"agree": sum(r["n"] for r in pairs if (r["a"] or "").lower() == (r["b"] or "").lower()),
                "total": sum(r["n"] for r in pairs)}

    return {
        "class": tally(live.filter(case__ai_assessment__isnull=False)
                       .values(a=F("result"), b=F("case__ai_assessment__result")).annotate(n=Count("pk"))),
        "verdict": tally(live.values(a=F("live_result"), b=F("would_be_result")).annotate(n=Count("pk"))),
    }


def age_warning(version, now=None):
    """True when the version was created (registered) more than 60 days ago."""
    return (now or timezone.now()) - version.created_at > timedelta(days=AGE_WARNING_DAYS)
