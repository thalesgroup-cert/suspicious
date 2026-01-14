from django.db import transaction
from django.db.models import Count
from django.contrib.auth.models import User
from dashboard.models import MonthlyReporterStats, MonthlyCasesSummary, TotalCasesStats
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


def update_monthly_cases_summary(kpi, current_month: int, current_year: int) -> None:
    """
    Update the monthly cases summary for a given KPI, for current month and year.
    """
    if kpi.monthly_cases_summary is None:
        kpi.monthly_cases_summary = MonthlyCasesSummary()

    case_counts = (
        Case.objects.filter(
            creation_date__month=current_month,
            creation_date__year=current_year
        )
        .values('results')
        .annotate(count=Count('results'))
    )

    for entry in case_counts:
        result_label = entry['results'].lower()
        field_name = f"{result_label}_cases"
        if hasattr(kpi.monthly_cases_summary, field_name):
            setattr(kpi.monthly_cases_summary, field_name, entry['count'])

    category_counts = (
        Case.objects.filter(
            creation_date__month=current_month,
            creation_date__year=current_year
        )
        .values('categoryAI')
        .annotate(count=Count('categoryAI'))
    )
    for entry in category_counts:
        category_label = entry['categoryAI'].lower()
        field_name = f"{category_label}_cases"
        if hasattr(kpi.monthly_cases_summary, field_name):
            setattr(kpi.monthly_cases_summary, field_name, entry['count'])

    kpi.monthly_cases_summary.save()


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
    update_monthly_cases_summary(kpi, current_month, current_year)
    update_total_cases_stats(kpi, current_month, current_year)
    kpi.save()
