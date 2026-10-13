"""Live dashboard summary over Case, optionally restricted to reporters in
every group of ``group_names`` (country / region / GBU, AND semantics as in
profiles.profiles_utils.scope).

A report counts in the month its case was created, in the server timezone:
the same bucket as the Investigation list's from/to date filter.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.db.models.functions import TruncWeek
from django.utils import timezone

from case_handler.models import Case, Result, Status
from profiles.profiles_utils.scope import restrict_to_groups

FINISHED = (Status.DONE, Status.CHALLENGED)  # a verdict exists
RUNNING = (Status.TODO, Status.ONGOING)
OUTCOMES = {
    "safe": Result.SAFE,
    "inconclusive": Result.INCONCLUSIVE,
    "suspicious": Result.SUSPICIOUS,
    "dangerous": Result.DANGEROUS,
    "failure": Result.FAILURE,
}
# AI sub-classifications counted as "malicious" by the legacy danger_counts
# (stored capitalised by cortex get_sub_class, with "_" or " ").
MALICIOUS_CATEGORIES = ("Classic_phishing", "Classic phishing", "Clone", "Blackmail", "Whaling")

_NO_FILE_OR_MAIL = Q(fileOrMail__file_id__isnull=True, fileOrMail__mail_id__isnull=True)
_NO_SINGLE_IOC = Q(
    nonFileIocs__url_id__isnull=True,
    nonFileIocs__ip_id__isnull=True,
    nonFileIocs__hash_id__isnull=True,
)
# Same precedence as api.serializers.investigations.get_case_type.
BY_TYPE = {
    "MAIL": Q(fileOrMail__file_id__isnull=True, fileOrMail__mail_id__isnull=False),
    "FILE": Q(fileOrMail__file_id__isnull=False),
    "URL": _NO_FILE_OR_MAIL & Q(nonFileIocs__url_id__isnull=False),
    "IP": _NO_FILE_OR_MAIL & Q(nonFileIocs__url_id__isnull=True, nonFileIocs__ip_id__isnull=False),
    "HASH": _NO_FILE_OR_MAIL
    & Q(nonFileIocs__url_id__isnull=True, nonFileIocs__ip_id__isnull=True, nonFileIocs__hash_id__isnull=False),
    "IOC": _NO_FILE_OR_MAIL & _NO_SINGLE_IOC & Q(observable_group_id__isnull=False),
    "UNKNOWN": _NO_FILE_OR_MAIL & _NO_SINGLE_IOC & Q(observable_group_id__isnull=True),
}
TOP_REPORTERS_LIMIT = 10


def month_bounds(month: int, year: int):
    """[start, end) of the month in the server timezone."""
    tz = timezone.get_current_timezone()
    start = timezone.make_aware(datetime(year, month, 1), tz)
    end = timezone.make_aware(datetime(year + month // 12, month % 12 + 1, 1), tz)
    return start, end


def _cases(month, year, group_names):
    start, end = month_bounds(month, year)
    qs = Case.objects.filter(creation_date__gte=start, creation_date__lt=end)
    if group_names is None:
        return qs
    # pk__in subquery: the group joins never fan out the aggregates below.
    return Case.objects.filter(pk__in=restrict_to_groups(qs, group_names).values("pk"))


def _counts(cases) -> dict:
    agg = cases.aggregate(
        reports=Count("pk"),
        in_progress=Count("pk", filter=Q(status__in=RUNNING)),
        reporters=Count("reporter", distinct=True),
        malicious=Count("pk", filter=Q(status__in=FINISHED, category_ai__in=MALICIOUS_CATEGORIES)),
        **{f"o_{k}": Count("pk", filter=Q(status__in=FINISHED, results=v)) for k, v in OUTCOMES.items()},
        **{f"t_{k}": Count("pk", filter=q) for k, q in BY_TYPE.items()},
    )
    return {
        "reports": agg["reports"],
        "outcomes": {k: agg[f"o_{k}"] for k in OUTCOMES},
        "in_progress": agg["in_progress"],
        "by_type": {k: agg[f"t_{k}"] for k in BY_TYPE},
        "reporters": agg["reporters"],
        "malicious": agg["malicious"],
    }


def _trend(cases, month, year) -> list[dict]:
    """Reports per ISO week (Monday start) touching the month, up to today; [] when empty."""
    per_week = {
        row["week"].date(): row["n"]
        for row in cases.annotate(week=TruncWeek("creation_date")).values("week").annotate(n=Count("pk"))
    }
    if not per_week:
        return []
    start, end = month_bounds(month, year)
    first = start.date() - timedelta(days=start.weekday())
    # Stop at today (server timezone, like month_bounds): weeks that have not
    # started are not zero-report weeks. Past months are unaffected.
    last = min((end - timedelta(days=1)).date(), timezone.localdate())
    weeks = []
    while first <= last:
        weeks.append({"week_start": first.isoformat(), "reports": per_week.get(first, 0)})
        first += timedelta(days=7)
    return weeks


def _top_reporters(cases) -> list[dict]:
    rows = cases.values_list("reporter__username").annotate(n=Count("pk"))
    suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", None)
    totals: dict[str, int] = defaultdict(int)
    for username, n in rows:
        if not username or username == suspicious_email:
            continue
        local, sep, _ = username.strip().partition("@")
        totals[local if sep else username.strip()] += n
    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:TOP_REPORTERS_LIMIT]
    return [{"label": label, "value": value} for label, value in ranked]


def _new_users(month, year, group_names) -> int:
    start, end = month_bounds(month, year)
    users = User.objects.filter(date_joined__gte=start, date_joined__lt=end)
    if group_names is not None:
        users = restrict_to_groups(users, group_names, lookup="groups__name")
    return users.count()


def summarise(month: int, year: int, group_names: list[str] | None, include_names: bool = False) -> dict:
    """Live summary for one month. ``group_names`` None means Overall."""
    cases = _cases(month, year, group_names)
    summary = _counts(cases)
    prev_month, prev_year = (12, year - 1) if month == 1 else (month - 1, year)
    previous = _counts(_cases(prev_month, prev_year, group_names))
    summary.update(
        new_users=_new_users(month, year, group_names),
        previous={"reports": previous["reports"], "outcomes": previous["outcomes"]},
        trend=_trend(cases, month, year),
        top_reporters=_top_reporters(cases) if include_names else None,
    )
    return summary
