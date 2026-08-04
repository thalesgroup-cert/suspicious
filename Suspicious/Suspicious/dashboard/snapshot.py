"""Standalone dashboard payload builder used by both the view and the
nightly materialisation task, so neither duplicates the query logic.
"""
from collections import defaultdict

from django.conf import settings
from django.db.models import Sum
from django.db.models.functions import Coalesce

from dashboard.models import (
    DashboardSnapshot,
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats,
)

_TOP_PREFIXES_LIMIT = 10
_SNAPSHOT_MAX_AGE_SECONDS = 86_400


def build_dashboard_payload(*, month: int, year: int, scope: str) -> dict:
    cases_agg = _get_cases_aggregate(month=month, year=year)
    reporters_agg = _get_reporters_aggregate(month=month, year=year)
    total_cases_agg = _get_total_cases_aggregate(month=month, year=year)
    challenged_agg = _get_challenged_cases_aggregate(month=month, year=year)

    malicious_total = (
        cases_agg["classic_phishing_cases"]
        + cases_agg["clone_cases"]
        + cases_agg["blackmail_cases"]
        + cases_agg["whaling_cases"]
    )

    return {
        "month": month,
        "year": year,
        "scope": scope,
        "kpis": {
            "new_users": reporters_agg["new_users"],
            "total_reporters": reporters_agg["total_reporters"],
            "total_cases": total_cases_agg["total_cases"],
            "challenged_cases": challenged_agg["challenged_cases"],
        },
        "danger_counts": {
            "failure": cases_agg["failure_cases"],
            "safe": cases_agg["safe_cases"],
            "inconclusive": cases_agg["inconclusive_cases"],
            "suspicious": cases_agg["suspicious_cases"],
            "dangerous": cases_agg["dangerous_cases"],
            "malicious": malicious_total,
        },
        "top_prefixes": _get_top_prefixes(month=month, year=year, limit=_TOP_PREFIXES_LIMIT),
    }


def get_snapshot(month: int, year: int) -> dict | None:
    """Return snapshot payload if one exists and is < 24 h old, else None."""
    from django.utils import timezone
    try:
        snap = DashboardSnapshot.objects.get(month=month, year=year)
        if (timezone.now() - snap.updated_at).total_seconds() < _SNAPSHOT_MAX_AGE_SECONDS:
            return snap.payload
    except DashboardSnapshot.DoesNotExist:
        pass
    return None


def materialise_snapshot(month: int, year: int) -> None:
    payload = build_dashboard_payload(month=month, year=year, scope="ALL")
    DashboardSnapshot.objects.update_or_create(
        month=month,
        year=year,
        defaults={"payload": payload},
    )


# ---------------------------------------------------------------------------
# Private query helpers
# ---------------------------------------------------------------------------

def _get_cases_aggregate(*, month: int, year: int) -> dict:
    return MonthlyCasesSummary.objects.filter(
        creation_date__month=month,
        creation_date__year=year,
    ).aggregate(
        failure_cases=Coalesce(Sum("failure_cases"), 0),
        safe_cases=Coalesce(Sum("safe_cases"), 0),
        inconclusive_cases=Coalesce(Sum("inconclusive_cases"), 0),
        suspicious_cases=Coalesce(Sum("suspicious_cases"), 0),
        dangerous_cases=Coalesce(Sum("dangerous_cases"), 0),
        classic_phishing_cases=Coalesce(Sum("classic_phishing_cases"), 0),
        clone_cases=Coalesce(Sum("clone_cases"), 0),
        blackmail_cases=Coalesce(Sum("blackmail_cases"), 0),
        whaling_cases=Coalesce(Sum("whaling_cases"), 0),
    )


def _get_reporters_aggregate(*, month: int, year: int) -> dict:
    return MonthlyReporterStats.objects.filter(
        creation_date__month=month,
        creation_date__year=year,
    ).aggregate(
        new_users=Coalesce(Sum("new_reporters"), 0),
        total_reporters=Coalesce(Sum("total_reporters"), 0),
    )


def _get_total_cases_aggregate(*, month: int, year: int) -> dict:
    return TotalCasesStats.objects.filter(
        creation_date__month=month,
        creation_date__year=year,
    ).aggregate(
        total_cases=Coalesce(Sum("total_cases"), 0),
    )


def _get_challenged_cases_aggregate(*, month: int, year: int) -> dict:
    # UserCasesMonthlyStats.month is written zero-padded (date.today().strftime("%m"),
    # see tasp/cron/kpi.py + tasp/services/challenge.py) - must match here or every
    # single-digit month (Jan-Sep) silently returns zero rows.
    return UserCasesMonthlyStats.objects.filter(
        month=f"{month:02d}",
        year=str(year),
    ).aggregate(
        challenged_cases=Coalesce(Sum("challenged_cases"), 0),
    )


def _get_top_prefixes(*, month: int, year: int, limit: int) -> list[dict]:
    month_str = str(month)
    year_str = str(year)
    suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", None)

    qs = UserCasesMonthlyStats.objects.filter(month=month_str, year=year_str)
    if suspicious_email:
        qs = qs.exclude(user__username=suspicious_email)

    totals_by_prefix: dict[str, int] = defaultdict(int)
    for username, total_cases in qs.values_list("user__username", "total_cases"):
        local, sep, _ = (username or "").strip().partition("@")
        label = local if sep == "@" else (username or "").strip()
        if label:
            totals_by_prefix[label] += int(total_cases or 0)

    sorted_items = sorted(
        totals_by_prefix.items(),
        key=lambda item: (-item[1], item[0]),
    )[:limit]

    return [{"label": label, "value": value} for label, value in sorted_items]
