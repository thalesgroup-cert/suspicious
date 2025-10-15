import logging
from typing import Literal, List, Tuple, Union, Dict, Set, Optional

from dashboard.models import Kpi, UserCasesMonthlyStats
from django import template
from django.contrib.auth.models import User
from django.db.models import Count as DbCount, Q, Sum
from django.template.defaultfilters import register
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})

register = template.Library()

logger = logging.getLogger(__name__)

DashboardData = List[Tuple[str, int]]

SUSPICIOUS_EMAIL: str = suspicious_config.get('suspicious_email', 'suspicious@cert.local')
SUSPICIOUS_EMAIL_USERNAME = "suspicious"
DANGER_LEVEL_SAFE = "safe"
DANGER_LEVEL_INCONCLUSIVE = "inconclusive"
DANGER_LEVEL_SUSPICIOUS = "suspicious"
DANGER_LEVEL_DANGEROUS = "dangerous"
DANGER_LEVEL_FAILURE = "failure"

VALID_DANGER_LEVELS: Set[str] = {
    DANGER_LEVEL_SAFE, DANGER_LEVEL_INCONCLUSIVE, DANGER_LEVEL_SUSPICIOUS,
    DANGER_LEVEL_DANGEROUS, DANGER_LEVEL_FAILURE
}
DANGER_FIELD_MAP: Dict[str, str] = {
    DANGER_LEVEL_SAFE: "safe_cases",
    DANGER_LEVEL_INCONCLUSIVE: "inconclusive_cases",
    DANGER_LEVEL_SUSPICIOUS: "suspicious_cases",
    DANGER_LEVEL_DANGEROUS: "dangerous_cases",
    DANGER_LEVEL_FAILURE: "failure_cases",
}

ALLOWED_DANGER_LEVELS = Literal[
    DANGER_LEVEL_SAFE,
    DANGER_LEVEL_INCONCLUSIVE,
    DANGER_LEVEL_SUSPICIOUS,
    DANGER_LEVEL_DANGEROUS,
    DANGER_LEVEL_FAILURE,
]

# Helper for month/year conversion and validation (DRY)
def _parse_month_year(
    month_str: Union[str, int], year_str: Union[str, int]
) -> Optional[Tuple[str, int]]:
    """Converts and validates month and year, returns (month_02d_str, year_int) or None."""
    try:
        month_int = int(month_str)
        year_int = int(year_str)
        if not (1 <= month_int <= 12 and year_int >= 1900): # Basic year validation
            logger.warning(f"Invalid month/year values: month={month_int}, year={year_int}")
            return None
        return f"{month_int:02d}", year_int
    except ValueError:
        logger.warning(f"Could not parse month/year: month='{month_str}', year='{year_str}'")
        return None

# Helper to get users in ALL specified groups (DRY)
def _get_users_in_all_groups_queryset(scope_str: str) -> Q:
    """
    Returns a Q object to filter users belonging to ALL groups in the scope string.
    If scope_str is empty or only whitespace, returns an empty Q object (no filter).
    """
    group_names = [g.strip() for g in scope_str.split('|') if g.strip()]
    if not group_names:
        return User.objects.all() # No group filter

    users_query = User.objects.all()
    for group_name in group_names:
        users_query = users_query.filter(groups__name=group_name)
    return users_query.distinct()

def dashboard_graph(
    num_emails: int, month: int, year: int
) -> List[Tuple[str, int]]:
    """
    Prepare top-reporter data for the dashboard.

    Args:
        num_emails: Maximum number of top reporters to retrieve.
        month:      Month (1–12) for which stats are fetched.
        year:       Four-digit year for which stats are fetched.

    Returns:
        A list of (username, total_cases) tuples for the top reporters,
        excluding the configured SUSPICIOUS_EMAIL.
    """
    qs = (
        UserCasesMonthlyStats.objects
        .filter(month=month, year=year)
        .exclude(user__username=SUSPICIOUS_EMAIL)
        .order_by("-total_cases")
        .values_list("user__username", "total_cases")
    )

    top_stats = qs[:num_emails]

    return list(top_stats)

@register.simple_tag(name="get_dashboard_email_prefix")
def get_dashboard_email_prefix(
    rank: int,
    num_emails: int,
    month: int,
    year: int
) -> str:
    """
    Django template tag: return the email prefix (before '@') at the given rank
    from the dashboard graph.

    Usage:
        {% load dashboard_tags %}
        {% get_dashboard_email_prefix rank num_emails month year as prefix %}
        Email #{{ rank }}: {{ prefix }}

    Args:
        rank:       1-based rank position (must be >= 1).
        num_emails: Total number of emails to include in the graph (must be >= 1).
        month:      Month number (1–12).
        year:       Four‑digit year (>= 1).

    Returns:
        The email prefix at the specified rank, or an empty string if inputs are invalid,
        the external call fails, or the rank is out of range.
    """
    # Validate and coerce inputs
    if any(not isinstance(arg, int) for arg in (rank, num_emails, year)):
        logger.error("get_dashboard_email_prefix: all arguments must be integers, got %r", (rank, num_emails, month, year))
        return ""
    if rank < 1:
        logger.error("get_dashboard_email_prefix: rank must be >= 1, got %d", rank)
        return ""
    if num_emails < 1:
        logger.error("get_dashboard_email_prefix: num_emails must be >= 1, got %d", num_emails)
        return ""
    if not (1 <= int(month) <= 12):
        logger.error("get_dashboard_email_prefix: month must be 1–12, got %d", month)
        return ""
    if year < 1:
        logger.error("get_dashboard_email_prefix: year must be >= 1, got %d", year)
        return ""

    try:
        data: DashboardData = dashboard_graph(num_emails, month, year)
    except Exception:
        logger.exception("get_dashboard_email_prefix: failed to generate dashboard data")
        return ""

    if 1 <= rank <= len(data):
        email, _ = data[rank - 1]
        # Safely split at '@'
        prefix = email.split("@", 1)[0]
        return prefix
    else:
        logger.info(
            "get_dashboard_email_prefix: requested rank %d out of range (1–%d)",
            rank, len(data)
        )
        return ""


@register.simple_tag(name="get_dashboard_score")
def get_dashboard_score(
    rank: int,
    num_emails: int,
    month: int,
    year: int
) -> str:
    """
    Django template tag: return the score at the given rank for the dashboard.

    Usage:
        {% load dashboard_tags %}
        {% get_dashboard_score rank num_emails month year as score %}
        Score #{{ rank }}: {{ score }}

    Args:
        rank:       1-based rank position (must be >= 1).
        num_emails: Number of emails (must be >= 1).
        month:      Month number (1–12).
        year:       Four‑digit year (>= 1).

    Returns:
        The score (as string) at the given rank, or an empty string if invalid
        inputs, out‑of‑range rank, or on error.
    """
    # Validate inputs
    if any(not isinstance(arg, int) for arg in (rank, num_emails, year)):
        logger.error("get_dashboard_score: all arguments must be integers, got %r", (rank, num_emails, month, year))
        return ""
    if rank < 1:
        logger.error("get_dashboard_score: rank must be >= 1, got %d", rank)
        return ""
    if num_emails < 1:
        logger.error("get_dashboard_score: num_emails must be >= 1, got %d", num_emails)
        return ""
    if not (1 <= int(month) <= 12):
        logger.error("get_dashboard_score: month must be 1–12, got %d", month)
        return ""
    if year < 1:
        logger.error("get_dashboard_score: year must be >= 1, got %d", year)
        return ""

    try:
        # Retrieve the list of (name, score) tuples from your graph function
        data: DashboardData = dashboard_graph(num_emails, month, year)
    except Exception:
        logger.exception("get_dashboard_score: failed to generate dashboard data")
        return ""

    # Check rank against data length
    if 1 <= rank <= len(data):
        _, score = data[rank - 1]
        return str(score)
    else:
        # Out‑of‑range rank
        logger.warning(
            "get_dashboard_score: requested rank %d out of range (1–%d)",
            rank, len(data)
        )
        return ""

def dashboard_graph_scope(
    num_emails: int,
    month: Union[str, int],
    year: Union[str, int],
    scope: str
) -> List[Tuple[str, float]]:
    """
    Prepares data for the top reporter graph.

    Retrieves top users by score for a given month, year, and scope (group membership),
    excluding a predefined suspicious email username. Users must belong to ALL specified groups.

    :param num_emails: The number of top users to retrieve (must be > 0).
    :param month: The month (1-12).
    :param year: The year.
    :param scope: A string representing group names, separated by ' | '.
                If empty or 'global' (case-insensitive), no group filter is applied.
    :return: A list of tuples (username, score).
    """
    if not isinstance(num_emails, int) or num_emails < 1:
        logger.warning(f"Invalid num_emails: {num_emails}. Must be a positive integer.")
        return []

    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return []
    month_str, year_int = parsed_date
    users_in_scope_q = User.objects.all()
    is_specific_scope = scope.strip() and scope.strip().lower() != 'global'

    if is_specific_scope:
        users_in_scope_q = _get_users_in_all_groups_queryset(scope)

    # Build the query for UserCasesMonthlyStats
    stats_query = UserCasesMonthlyStats.objects.filter(
        month=month_str,
        year=year_int
    ).select_related('user')

    if is_specific_scope:
        stats_query = stats_query.filter(user__in=users_in_scope_q)

    stats_query = stats_query.exclude(
        user__username=SUSPICIOUS_EMAIL_USERNAME
    ).order_by('-score')

    top_stats = stats_query[:num_emails]

    results = [
        (stat.user.username, stat.score)
        for stat in top_stats if stat.user
    ]
    return results


@register.simple_tag
def dashboard_mail_scope(
    rank: int,
    num_emails: int,
    month: Union[str, int],
    year: Union[str, int],
    scope: str
) -> str:
    """
    Returns the username (part before '@' if applicable) for a given rank from the top reporters.

    :param rank: The rank (1-based) of the email/username to retrieve.
    :param num_emails: The total number of top emails considered.
    :param month: The month (1-12).
    :param year: The year.
    :param scope: Group scope string.
    :return: Username part of email, or empty string if not found/invalid.
    """
    if not (isinstance(rank, int) and isinstance(num_emails, int) and \
            1 <= rank <= num_emails and num_emails >= 1):
        logger.warning(f"Invalid rank/num_emails: rank={rank}, num_emails={num_emails}")
        return ""

    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return ""
    month_val, year_val = parsed_date

    names_scores = dashboard_graph_scope(num_emails, month_val, year_val, scope)

    if 0 < rank <= len(names_scores):
        username = names_scores[rank - 1][0]
        return username.split('@')[0] if '@' in username else username
    return ""

@register.simple_tag
def dashboard_score_scope(
    rank: int,
    num_emails: int,
    month: Union[str, int],
    year: Union[str, int],
    scope: str
) -> Union[float, int, str]: # Score could be float/int, empty string on failure
    """
    Returns the score for a given rank from the top reporters.

    :param rank: The rank (1-based) of the score to retrieve.
    :param num_emails: The total number of top emails considered.
    :param month: The month (1-12).
    :param year: The year.
    :param scope: Group scope string.
    :return: Score, or empty string if not found/invalid (or 0 for numeric consistency).
    """
    if not (isinstance(rank, int) and isinstance(num_emails, int) and \
            1 <= rank <= num_emails and num_emails >= 1):
        logger.warning(f"Invalid rank/num_emails: rank={rank}, num_emails={num_emails}")
        return ""

    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return ""
    month_val, year_val = parsed_date

    names_scores = dashboard_graph_scope(num_emails, month_val, year_val, scope)

    if 0 < rank <= len(names_scores):
        score = names_scores[rank - 1][1]
        return score
    return ""


@register.filter(name="total_reporters_dash_scope")
def total_reporters_dash_scope(
    scope: str,
    month: Union[str, int],
    year: Union[str, int]
) -> int:
    """
    Calculates the total number of unique active reporters for a given month, year, and scope.
    An active reporter is a user with UserCasesMonthlyStats records for the period,
    belonging to ALL specified groups.

    :param scope: Group scope string. Users must belong to ALL groups.
    :param month: The month (1-12).
    :param year: The year.
    :return: Total count of unique reporters.
    """
    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    month_str, year_int = parsed_date

    users_in_scope_q = UserCasesMonthlyStats.objects.filter(
        month=month_str,
        year=year_int
    )

    group_names = [g.strip() for g in scope.split('|') if g.strip()]
    if group_names:
        user_filter_q = Q()
        for group_name in group_names:
            user_filter_q &= Q(user__groups__name=group_name)
        users_in_scope_q = users_in_scope_q.filter(user_filter_q)

    # Count distinct users
    report_count = users_in_scope_q.aggregate(
        distinct_reporters=DbCount('user', distinct=True)
    )
    return report_count.get('distinct_reporters', 0)


@register.filter(name="get_case_all_dash_scope")
def get_case_all_dash_scope(
    scope: str,
    month: Union[str, int],
    year: Union[str, int]
) -> int:
    """
    Returns the total number of cases for users in a given month, year, and scope.
    Users must belong to ALL specified groups.

    :param scope: Group scope string.
    :param month: The month (1-12).
    :param year: The year.
    :return: Total number of cases, or 0 on error/no data.
    """
    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    month_str, year_int = parsed_date

    stats_query = UserCasesMonthlyStats.objects.filter(
        month=month_str,
        year=year_int
    )

    group_names = [g.strip() for g in scope.split('|') if g.strip()]
    if group_names:
        user_filter_q = Q()
        for group_name in group_names:
            user_filter_q &= Q(user__groups__name=group_name)
        stats_query = stats_query.filter(user_filter_q)

    try:
        aggregation = stats_query.aggregate(total_sum=Sum('total_cases'))
        return aggregation.get('total_sum') or 0
    except Exception as e:
        logger.error(f"Error in get_case_all_dash_scope for {month_str}/{year_int}, scope='{scope}': {e}")
        return 0


@register.filter(name="new_reporters_dash_scope")
def new_reporters_dash_scope(
    scope: str,
    month: Union[str, int],
    year: Union[str, int]
) -> int:
    """
    Counts users who joined within a specific month and year AND belong to ALL specified groups.

    :param scope: Group scope string. Users must belong to ALL groups.
    :param month: The month (1-12).
    :param year: The year.
    :return: Count of new users meeting criteria.
    """
    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    _, year_int = parsed_date
    try:
        month_int = int(month)
    except ValueError:
        return 0
    users_query = User.objects.filter(date_joined__year=year_int, date_joined__month=month_int)

    group_names = [g.strip() for g in scope.split('|') if g.strip()]
    if group_names:
        for group_name in group_names:
            users_query = users_query.filter(groups__name=group_name)

    return users_query.distinct().count()


@register.filter(name="total_by_danger_dash_scope")
def total_by_danger_dash_scope(
    danger: str,
    month: Union[str, int],
    year: Union[str, int],
    scope: str
) -> int:
    """
    Calculates total cases of a specific danger level for a given month, year, and scope.
    Users must belong to ALL specified groups.

    :param danger: The danger level string (e.g., "safe", "dangerous").
    :param month: The month (1-12).
    :param year: The year.
    :param scope: Group scope string.
    :return: Total count for the specified danger level.

    """
    if danger not in VALID_DANGER_LEVELS:
        logger.warning(f"Invalid danger level provided: {danger}")
        return 0

    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    month_str, year_int = parsed_date

    target_field = DANGER_FIELD_MAP.get(danger)
    if not target_field:
        logger.error(f"Danger level '{danger}' has no mapped field.")
        return 0

    stats_query = UserCasesMonthlyStats.objects.filter(
        month=month_str,
        year=year_int
    )

    group_names = [g.strip() for g in scope.split('|') if g.strip()]
    if group_names:
        user_filter_q = Q()
        for group_name in group_names:
            user_filter_q &= Q(user__groups__name=group_name)
        stats_query = stats_query.filter(user_filter_q)

    try:
        aggregation = stats_query.aggregate(total_sum=Sum(target_field))
        return aggregation.get('total_sum') or 0
    except Exception as e:
        logger.error(f"Error in total_by_danger_dash_scope for {danger}, {month_str}/{year_int}, scope='{scope}': {e}")
        return 0

@register.filter(name="total_reporters_dash")
def total_reporters_dash(month: Union[str, int], year: Union[str, int]) -> int:
    """
    Returns the total number of unique reporters for a given month and year.
    This version reads pre-calculated statistics from Kpi.monthly_reporter_stats.total_reporters
    or calculates it directly from UserCasesMonthlyStats if Kpi path is not viable.
    IT DOES NOT CREATE OR UPDATE DATABASE RECORDS.

    :param month: The month (1-12).
    :param year: The year.
    :return: Total number of reporters, or 0 if not found/error.
    """
    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    month_str, year_int = parsed_date

    try:
        kpi = Kpi.objects.filter(month=month_str, year=year_int).select_related('monthly_reporter_stats').first()
        if kpi and kpi.monthly_reporter_stats and hasattr(kpi.monthly_reporter_stats, 'total_reporters'):
            return kpi.monthly_reporter_stats.total_reporters or 0
    except Exception as e: # Catch specific exceptions if possible
        logger.error(f"Error trying to fetch pre-aggregated total_reporters for {month_str}/{year_int}: {e}")
    try:
        report_count = UserCasesMonthlyStats.objects.filter(
            month=month_str,
            year=year_int
        ).aggregate(distinct_reporters=DbCount('user', distinct=True))
        return report_count.get('distinct_reporters', 0)
    except Exception as e:
        logger.error(f"Error calculating total_reporters_dash directly for {month_str}/{year_int}: {e}")
        return 0


@register.filter(name="get_case_all_dash")
def get_case_all_dash(month: Union[str, int], year: Union[str, int]) -> int:
    """
    Retrieves the total number of cases for a given month and year.
    Reads from Kpi.total_cases_stats.total_cases or calculates directly.
    IT DOES NOT CREATE OR UPDATE DATABASE RECORDS.

    :param month: The month (1-12).
    :param year: The year.
    :return: Total number of cases, or 0 if not found/error.
    """
    parsed_date = _parse_month_year(month, year)
    if not parsed_date:
        return 0
    month_str, year_int = parsed_date

    try:
        kpi = Kpi.objects.filter(month=month_str, year=year_int).select_related('total_cases_stats').first()
        if kpi and kpi.total_cases_stats and hasattr(kpi.total_cases_stats, 'total_cases'):
            return kpi.total_cases_stats.total_cases or 0
    except Exception as e:
        logger.error(f"Error trying to fetch pre-aggregated total_cases for {month_str}/{year_int}: {e}")

    try:
        aggregation = UserCasesMonthlyStats.objects.filter(
            month=month_str,
            year=year_int
        ).aggregate(total_sum=Sum('total_cases'))
        return aggregation.get('total_sum') or 0
    except Exception as e:
        logger.error(f"Error calculating get_case_all_dash directly for {month_str}/{year_int}: {e}")
        return 0


@register.filter(name="new_reporters_dash")
def new_reporters_dash(
    month: Union[str, int],
    year: Union[str, int]
) -> int:
    """
    Returns the number of new reporters for a given month and year.

    This filter reads from existing Kpi records and does not create new ones.
    It expects a Kpi object to have a 'monthly_reporter_stats' attribute,
    which in turn has a 'new_reporters' attribute.

    :param month: The month (1-12) for which the count is fetched. Can be string or int.
    :type month: Union[str, int]
    :param year: The year for which the count is fetched. Can be string or int.
    :type year: Union[str, int]
    :return: The number of new reporters, or 0 if data is not available or an error occurs.
    :rtype: int

    Example usage in Django Template:
    ``{{ some_month_variable|new_reporters_dash:some_year_variable }}``
    ``{{ "5"|new_reporters_dash:2022 }}``
    """
    try:
        month_int = int(month)
        year_int = int(year)
        if not (1 <= month_int <= 12):
            logger.warning(f"Invalid month: {month}")
            return 0
    except ValueError:
        logger.error(f"Invalid month/year format: month={month}, year={year}")
        return 0

    month_str = f"{month_int:02d}"

    try:
        kpi = Kpi.objects.filter(month=month_str, year=year_int).first()

    except Exception as e:
        logger.error(f"Error fetching Kpi for {month_str}/{year_int}: {e}")
        return 0

    if not kpi:
        return 0
    reporter_stats = getattr(kpi, 'monthly_reporter_stats', None)
    if not reporter_stats:
        return 0

    new_reporters_count = getattr(reporter_stats, 'new_reporters', 0)
    return new_reporters_count if isinstance(new_reporters_count, int) else 0


@register.filter(name="total_by_danger_dash")
def total_by_danger_dash(
    danger: ALLOWED_DANGER_LEVELS,
    month: Union[str, int],
    year: Union[str, int]
) -> int:
    """
    Returns the total number of cases based on the danger level for a given month and year.

    Parameters:
    - danger (ALLOWED_DANGER_LEVELS): The danger level of the cases.
    Possible values are "safe", "inconclusive", "suspicious", "dangerous", and "failure".
    - month (Union[str, int]): The month (1-12) for which the cases are counted.
    - year (Union[str, int]): The year for which the cases are counted.

    Returns:
    - int: The total number of cases based on the danger level, or 0 if not found or an error occurs.

    Example usage in Django Template:
    {{ "safe"\|total_by_danger_dash:5:2022 }}  {# Returns the total number of safe cases for May 2022 #}
    """
    try:
        month_int = int(month)
        year_int = int(year)
        if not (1 <= month_int <= 12):
            logger.warning(f"Invalid month provided: {month}")
            return 0
    except ValueError:
        logger.error(f"Could not convert month/year to int: month={month}, year={year}")
        return 0

    month_str = f"{month_int:02d}"
    try:
        kpi = Kpi.objects.filter(month=month_str, year=year_int).first()

    except Exception as e:
        logger.error(f"Error fetching Kpi data for {month_str}/{year_int}: {e}")
        return 0

    if not kpi:
        return 0

    summary = getattr(kpi, 'monthly_cases_summary', None)
    if not summary:
        return 0

    attribute_name = f"{danger}_cases"
    value = getattr(summary, attribute_name, 0)

    return value if isinstance(value, int) else 0
