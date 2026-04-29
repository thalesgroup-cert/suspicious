from django.db import transaction
from django.db.models import Count
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from dashboard.models import MonthlyReporterStats, MonthlyCasesSummary, TotalCasesStats, GroupMonthlyStats
from case_handler.models import Case


def update_monthly_reporter_stats(kpi, current_month: int, current_year: int) -> None:
    """
    Update the monthly reporter statistics for a given KPI.
    Creates or updates MonthlyReporterStats.
    """
    new_reporters_count = User.objects.filter(
        date_joined__month=current_month,
        date_joined__year=current_year
    ).count()

    # Calculate unique reporters for current month
    total_reporters_count = Case.objects.filter(
        creation_date__month=current_month,
        creation_date__year=current_year
    ).values_list("reporter", flat=True).distinct().count()

    if kpi.monthly_reporter_stats is None:
        kpi.monthly_reporter_stats = MonthlyReporterStats.objects.create(
            total_reporters=total_reporters_count,
            new_reporters=new_reporters_count
        )
    else:
        kpi.monthly_reporter_stats.new_reporters = new_reporters_count
        kpi.monthly_reporter_stats.save()

def update_group_monthly_stats(current_month: int, current_year: int) -> None:
    """
    Update monthly statistics for each group for the given month and year.
    Creates or updates one GroupMonthlyStats row per group.
    """
    groups = Group.objects.all()

    for group in groups:
        base_qs = Case.objects.filter(
            creation_date__month=current_month,
            creation_date__year=current_year,
            reporter__groups=group
        )

        group_stat, _ = GroupMonthlyStats.objects.get_or_create(
            group_name=group.name,
            month=str(current_month),
            year=str(current_year),
        )

        # Reset all counters before recomputing
        group_stat.total_cases = base_qs.count()
        group_stat.suspicious_cases = 0
        group_stat.inconclusive_cases = 0
        group_stat.failure_cases = 0
        group_stat.dangerous_cases = 0
        group_stat.safe_cases = 0
        group_stat.challenged_cases = 0
        group_stat.allow_listed_cases = 0

        group_stat.uncategorized_cases = 0
        group_stat.spam_cases = 0
        group_stat.newsletter_cases = 0
        group_stat.classic_phishing_cases = 0
        group_stat.clone_cases = 0
        group_stat.blackmail_cases = 0
        group_stat.whaling_cases = 0
        group_stat.internal_cases = 0
        group_stat.external_cases = 0

        # Count by results
        result_counts = (
            base_qs.values('results')
            .annotate(count=Count('results'))
        )

        for entry in result_counts:
            raw = entry['results']
            if not raw:
                continue
            field_name = f"{raw.lower()}_cases"
            if hasattr(group_stat, field_name):
                setattr(group_stat, field_name, entry['count'])

        # Count challenged cases
        group_stat.challenged_cases = base_qs.filter(is_challenged=True).count()

        # Count by categoryAI
        category_counts = (
            base_qs.values('categoryAI')
            .annotate(count=Count('categoryAI'))
        )

        for entry in category_counts:
            raw = entry['categoryAI']
            if not raw:
                continue
            field_name = f"{raw.lower().replace(' ', '_')}_cases"
            if hasattr(group_stat, field_name):
                setattr(group_stat, field_name, entry['count'])

        group_stat.save()

def update_monthly_cases_summary(kpi, current_month: int, current_year: int) -> None:
    """
    Update the monthly cases summary for a given KPI, for current month and year.
    """
    if kpi.monthly_cases_summary is None:
        kpi.monthly_cases_summary = MonthlyCasesSummary()

    summary = kpi.monthly_cases_summary

    # Reset all counters before recomputing to avoid stale data from previous runs
    for field in MonthlyCasesSummary._meta.get_fields():
        if hasattr(field, 'default') and field.name.endswith('_cases'):
            setattr(summary, field.name, 0)

    case_counts = (
        Case.objects.filter(
            creation_date__month=current_month,
            creation_date__year=current_year
        )
        .values('results')
        .annotate(count=Count('results'))
    )

    for entry in case_counts:
        raw = entry['results']
        if not raw:
            continue
        field_name = f"{raw.lower()}_cases"
        if hasattr(summary, field_name):
            setattr(summary, field_name, entry['count'])

    category_counts = (
        Case.objects.filter(
            creation_date__month=current_month,
            creation_date__year=current_year
        )
        .values('categoryAI')
        .annotate(count=Count('categoryAI'))
    )
    for entry in category_counts:
        raw = entry['categoryAI']
        if not raw:
            continue
        field_name = f"{raw.lower()}_cases"
        if hasattr(summary, field_name):
            setattr(summary, field_name, entry['count'])

    summary.save()


def update_total_cases_stats(kpi, current_month: int, current_year: int) -> None:
    """
    Update the total cases statistics for a given KPI.
    """
    total = Case.objects.filter(
        creation_date__month=current_month,
        creation_date__year=current_year
    ).count()

    if kpi.total_cases_stats is None:
        kpi.total_cases_stats = TotalCasesStats.objects.create(total_cases=total)
    else:
        kpi.total_cases_stats.total_cases = total
        kpi.total_cases_stats.save()


@transaction.atomic
def update_all_kpi_stats(kpi, current_month: int, current_year: int) -> None:
    """
    Safely updates all KPI statistics in one atomic transaction.
    """
    update_monthly_reporter_stats(kpi, current_month, current_year)
    update_group_monthly_stats(current_month, current_year)
    update_monthly_cases_summary(kpi, current_month, current_year)
    update_total_cases_stats(kpi, current_month, current_year)
    kpi.save()
