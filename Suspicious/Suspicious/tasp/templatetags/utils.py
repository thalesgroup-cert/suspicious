"""
Utility functions for Django templates.
These functions are used to manipulate and format data for display in templates.
"""

import calendar
import logging
import os
from datetime import date
from datetime import datetime as dt
from email.header import decode_header
from typing import Final, List, Optional, Tuple, Union

from case_handler.models import Case
from dashboard.models import Kpi, UserCasesMonthlyStats
from django import template
from django.contrib.auth.models import User
from django.db.models import Count, Sum
from django.utils.text import Truncator
from domain_process.domain_utils.domain_handler import DomainHandler
from hash_process.hash_utils.hash_handler import HashHandler
from ip_process.ip_utils.ip_handler import IPHandler
from profiles.models import CISOProfile , UserProfile
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})

SUSPICIOUS_EMAIL: str = suspicious_config.get('email', 'suspicious@local.com')
_SITE_LINK: Final[str] = suspicious_config.get('link', 'https://example.com')
_FOOTER_TEXT: Final[str] = suspicious_config.get('footer', 'All rights reserved.')
MAX_SUBJECT_LENGTH: int = 20
RANDOM_SUFFIX_BYTES: Final[int] = 8
# Define the allowed danger levels
DashboardData = List[Tuple[str, int]]

country_dict = {
    "AR", "BO", "BR", "CL", "CO", "MX", "PE", "UY", "VE", "BS", "CA", "CR", "DO", "GT", "HN", "HT", "JM", "MX", "NI", 
    "PA", "PR", "SV", "US", "AE", "AT", "AZ", "BE", "BG", "BH", "CM", "CI", "CZ", "DE", "DZ", "DK", "EE", "EG", "ES", 
    "ET", "FI", "FR", "GB", "GR", "HK", "HU", "IE", "IL", "IQ", "IT", "JO", "KE", "KW", "KZ", "LB", "LT", "LU", "LV", 
    "MA", "MD", "MK", "MT", "MY", "NG", "NL", "NO", "OM", "PK", "PL", "PT", "QA", "RO", "RS", "RU", "SA", "SE", "SG", 
    "SI", "SK", "SN", "SY", "TD", "TN", "TR", "UA", "UG", "UZ", "ZA", "AU", "CN", "HK", "ID", "IN", "JP", "KR", "MY", 
    "NZ", "PH", "SG", "TH", "TW", "VN"
}
region_dict = {
    "LATAM",
    "NORAM",
    "EMEA",
    "APAC"
}
logger = logging.getLogger(__name__)

register = template.Library()


@register.filter(name='get_theme')
def get_theme(user):
    """
    Returns the theme preference of the user.

    This function is used in Django templates to set the theme (light or dark) based on user preference.

    Args:
        user (User): The user object.

    Returns:
        str: The theme preference of the user ('light' or 'dark').
    """
    try:
        profile =  UserProfile.objects.filter(user=user).first()
        return profile.theme if profile and profile.theme in ['light', 'dark', 'default', 'valentine', 'sunrise', 'midnight', 'cyber'] else 'light'
    except Exception as e:
        logger.error(f"Error retrieving theme for user {user.username}: {str(e)}", exc_info=True)
        return 'light'

@register.simple_tag(name='get_ico')
def get_ico():
    """
    Returns the path to the favicon.ico file.

    This function is used in Django templates to include the favicon in the HTML head section.

    Returns:
        str: The path to the favicon.ico file.
    """
    # Assuming the favicon.ico is located in the static files directory
    return suspicious_config.get('ico')

@register.simple_tag(name='get_sign')
def get_sign():
    """
    Returns the path to the sign file.

    This function is used in Django templates to include the favicon in the HTML head section.

    Returns:
        str: The path to the sign file.
    """
    # Assuming the favicon.ico is located in the static files directory
    return suspicious_config.get('sign')

@register.simple_tag(name='get_logo')
def get_logo():
    """
    Returns the path to the logo image file.

    This function is used in Django templates to include the logo in the HTML head section.

    Returns:
        str: The path to the logo image file.
    """
    # Assuming the logo is located in the static files directory
    return suspicious_config.get('logo')

@register.simple_tag(name='get_banner')
def get_banner():
    """
    Returns the path to the banner image file.

    This function is used in Django templates to include the banner in the HTML head section.

    Returns:
        str: The path to the banner image file.
    """
    # Assuming the banner is located in the static files directory
    return suspicious_config.get('banner')


@register.filter(name='has_group')
def has_group(user, group_name):
    """
    Check if the user is part of a specific group.

    Args:
        user (User): The user object.
        group_name (str): The name of the group to check.

    Returns:
        bool: True if the user is part of the group, False otherwise.
    """
    if user is None or group_name is None:
        return False

    if not user.is_authenticated:
        return False

    return user.groups.filter(name=group_name).exists()

@register.filter
def has_group_elevated(user):
    '''Function used to check if the user is part of the elevated group.

    Args:
        user (User): The user object to check.

    Returns:
        bool: True if the user is part of the elevated group, False otherwise.
    '''
    elevated_groups = ['Admin', 'CERT', 'Champions']
    if user.groups.filter(name__in=elevated_groups).exists():
        return True
    is_ciso = CISOProfile.objects.filter(user=user).exists()
    return is_ciso

@register.filter
def is_ciso(user):
    '''Function used to check if the user is part of the CISO group

    Args:
        user (User): The user object to check

    Returns:
        bool: True if the user is part of the CISO group, False otherwise
    '''
    try:
        CISOProfile.objects.get(user=user)
        return True
    except CISOProfile.DoesNotExist:
        return False

@register.filter
def get_groups(user):
    """
    Returns a list of groups that the user is a part of.

    Parameters:
    - user: The user object for which to retrieve the groups.

    Returns:
    - A list of group names that the user is a part of. If the user is a CISO, it returns ["CISO"].
    """
    # Use get() instead of filter().first() for better performance
    try:
        is_ciso = CISOProfile.objects.get(user=user)
        if is_ciso:
            return ["CISO"]
    except CISOProfile.DoesNotExist:
        pass
    # Use values_list() to get a list of group names directly
    # Set flat=True to return a flat list instead of a list of tuples
    return user.groups.values_list('name', flat=True)


@register.filter
def ciso_scope(user):
    """
    Returns the scope of a CISO (Chief Information Security Officer) user.

    Args:
        user (User): The user object for which to retrieve the scope.

    Returns:
        str: The scope of the CISO user, separated by '|' characters.

    """
    is_ciso = CISOProfile.objects.get(user=user)
    if is_ciso and is_ciso.scope:
        scopes = is_ciso.scope.split(';')
        ciso_scope = " | ".join(scopes)
        return ciso_scope
    return ''


@register.filter
def get_scope_cases_number(user):
    """
    Returns the total number of cases within the scope of the given user.

    Parameters:
    - user: The user for whom to calculate the scope cases.

    Returns:
    - scope_cases: The total number of cases within the user's scope.
    """
    today = date.today()
    year = today.year
    month = today.month
    if len(str(month)) == 1:
        month = "0" + str(month)
    scope_cases = 0
    is_ciso = CISOProfile.objects.filter(user=user).first()
    if is_ciso:
        groups = is_ciso.scope.split(' | ')
        users = User.objects.filter(groups__name__in=groups)
        # keep only users that have all groups from the scope
        users = users.annotate(group_count=Count('groups')).filter(group_count=len(groups))
        total_reporters = UserCasesMonthlyStats.objects.filter(month=month, year=year ,user__in=users)
        scope_cases = total_reporters.aggregate(total_cases=Sum('total_cases'))['total_cases']
    return scope_cases or 0

@register.filter
def get_related_field(case_id, field):
    '''
    Retrieve a related field value based on the given case_id and field.

    Parameters:
    - case_id (int): The ID of the Case object.
    - field (str): The field name to retrieve.

    Returns:
    - The value of the specified field for the related object, or None if the object does not exist.

    Raises:
    - None.

    '''
    # Define the fields that are related to File and User models
    file_related_fields = ['filetype', 'file_path']
    user_related_fields = ['first_name', 'email']

    # Try to get the Case object with the given case_id
    case = Case.objects.filter(pk=case_id).first()
    if not case:
        return None

    # If the field is related to File model
    if field in file_related_fields:
        # Try to get the File object with the file_id of the Case object
        file = getattr(case, 'fileOrMail', None)
        if file:
            file = getattr(file, 'file', None)
        if file:
            return getattr(file, field, None)

    # If the field is related to User model
    elif field in user_related_fields:
        # Try to get the User object with the user_id of the Case object
        user = getattr(case, 'reporter', None)
        if user:
            if field == 'email':
                return getattr(user, 'username', None)
            elif field == 'first_name':
                email = str(user)
                return email.split('@')[0]
            return getattr(user, field, None)

    return None


@register.filter
def get_region(user_groups):
    """
    Returns the region associated with the user groups.

    Args:
        user_groups (QuerySet): A Django QuerySet of user groups.

    Returns:
        str: The name of the region associated with the user groups.
            If no region is found, an empty string is returned.
    """
    # Convert the region_dict to a set for faster lookup
    region_set = set(region_dict)

    # Use the built-in next function with a generator expression to find the first group in user_groups that is in region_set
    # This is more efficient than using a for loop and breaking on the first match
    # If no match is found, next will return an empty string
    region = next((group.name for group in user_groups if group.name in region_set), "")

    return region

@register.filter
def get_country(user_groups):
    """
    Returns the country name associated with the user groups.

    Args:
        user_groups (QuerySet): A QuerySet of user groups.

    Returns:
        str: The name of the country associated with the user groups.
    """
    # Use set intersection to find the common elements between user_groups and country_dict
    # This is more efficient than looping through each group
    # Also, it will return all matching countries, not just the first one found
    user_group_names = set(group.name for group in user_groups)
    matching_countries = user_group_names & country_dict

    # If there are multiple matching countries, join them with a comma
    country = ', '.join(matching_countries)

    return country

@register.filter
def get_gbu(user_groups):
    """
    Returns the GBU (Global Business Unit) name from a list of user groups.

    Args:
        user_groups (list): A list of user groups.

    Returns:
        str: The GBU name.

    """
    # Using a generator expression to find the first group name that is not in country_dict and region_dict
    # This is more efficient as it stops as soon as it finds the first match
    gbu = next((group.name for group in user_groups if group.name not in country_dict and group.name not in region_dict), "")
    return gbu

@register.filter
def change_date_format(pubdate):
    """
    Converts the given pubdate to a new date format.

    Args:
        pubdate (datetime): The original publication date.

    Returns:
        str: The new date formatted as "YYYY-MM-DD HH:MM".
    """
    # Check if pubdate is not None and is an instance of datetime
    if pubdate and isinstance(pubdate, dt):
        new_date = pubdate.strftime("%Y-%m-%d %H:%M") 
        return new_date
    else:
        return "Invalid datetime object"


@register.filter(name="email_username")
def email_username(email: Optional[str]) -> str:
    """
    Django template filter: extract the username part (before "@") of an email.

    Usage in template:
        {% load email_tags %}
        {{ user.email|email_username }}

    Args:
        email: The full email address as a string, or None.

    Returns:
        The local‑part of the email (before "@"), or an empty string if input is falsy
        or doesn’t contain a valid "@".
    """
    if not email:
        return ""  # Handles None or empty strings gracefully
    username, sep, _ = email.strip().partition("@")
    return username if sep == "@" and username else ""  # Safe, no exceptions


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
    # Build a QuerySet that filters by month/year and excludes the system user
    qs = (
        UserCasesMonthlyStats.objects
        .filter(month=month, year=year)                                  # restrict by date 
        .exclude(user__username=SUSPICIOUS_EMAIL)               # filter out noise 
        .order_by("-total_cases")                                        # sort descending by cases 
        .values_list("user__username", "total_cases")                    # fetch only needed fields 
    )

    # Slice the QuerySet before evaluation to apply SQL LIMIT num_emails 
    top_stats = qs[:num_emails]

    # Convert to a list of tuples and return
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


@register.simple_tag(name="total_cases_this_month")
def total_cases_this_month() -> int:
    """
    Django template tag: returns the total number of cases for the current month.

    Usage in template:
        {% load kpi_tags %}
        Total cases this month: {% total_cases_this_month %}

    Returns:
        int: The 'total_cases' attribute from the KPI's total_cases_stats,
            or 0 if an error occurs or data is missing.
    """
    try:
        from tasp.cron.kpi import sync_monthly_kpi as fetch_kpis
        kpi = fetch_kpis()  # your cron function returns a KPI instance
        stats = getattr(kpi, "total_cases_stats", None)  # safe access
        if stats is None:
            logger.warning("KPI missing 'total_cases_stats' attribute")  # signal missing data
            return 0
        return getattr(stats, "total_cases", 0)  # default to 0 if missing
    except Exception:
        logger.exception("Unexpected error retrieving total cases for this month")  # full traceback
        return 0


@register.simple_tag(name="monthly_new_reporters")
def monthly_new_reporters() -> int:
    """
    Django template tag: returns the number of new reporters for the current month.

    Usage in a template:
        {% load report_tags %}
        New reporters this month: {% monthly_new_reporters %}

    Returns:
        int: The 'new_reporters' value from the current KPI, or 0 on error or if missing.
    """
    try:
        from tasp.cron.kpi import sync_monthly_kpi as fetch_kpis
        kpi = fetch_kpis()  # should return an object with monthly_reporter_stats
        stats = getattr(kpi, "monthly_reporter_stats", None)
        if stats is None:
            logger.warning("KPI missing 'monthly_reporter_stats' attribute")  # avoid silent failure
            return 0
        return getattr(stats, "new_reporters", 0)  # default to 0 if attribute missing
    except Exception:
        logger.exception("Unexpected error computing new reporters")  # full traceback
        return 0


@register.filter(name="total_cases_by_danger_level")
def total_cases_by_danger_level(
    danger: str
) -> int:
    """
    Django template tag: returns the total number of cases for a given danger level.

    Usage in a template:
        {% load kpi_tags %}
        {% total_cases_by_danger_level "safe" as safe_count %}
        Safe cases: {{ safe_count }}

    Args:
        danger: One of "safe", "inconclusive", "suspicious", "dangerous", "failure".

    Returns:
        The integer count of total cases for that danger level, or 0 if not found or on error.
    """
    # Validate danger level
    valid_levels = {"safe", "inconclusive", "suspicious", "dangerous", "failure"}
    if danger not in valid_levels:
        logger.error("Invalid danger level passed to tag: %r", danger)
        return 0  # fail safe on invalid input

    # Map danger level to model field
    field_map = {
        "safe":         "safe_cases",
        "inconclusive": "inconclusive_cases",
        "suspicious":   "suspicious_cases",
        "dangerous":    "dangerous_cases",
        "failure":      "failure_cases",
    }

    try:
        # Fetch latest KPI record (adjust filter as needed) and get the summary
        kpi = Kpi.objects.order_by("-year", "-month").first()  # most recent
        if not kpi:
            return 0

        summary = kpi.monthly_cases_summary
        # Use getattr with default to 0 for safety
        return getattr(summary, field_map[danger], 0)
    except Exception:
        # Log full traceback for debugging
        logger.exception(
            "Error retrieving cases for danger=%r", danger
        )
        return 0




@register.simple_tag(name="monthly_reporters_count")
def monthly_reporters_count() -> int:
    """
    Django template tag: returns the total number of reporters for the current month and year.

    Usage:
        {% load report_tags %}
        Total reporters this month: {% monthly_reporters_count %}

    Returns:
        int: The total_reporters from the KPI object for the current month/year.

    Raises:
        ValueError: if the KPI record is not found or missing the attribute.
    """
    try:
        from tasp.cron.kpi import sync_monthly_kpi as fetch_kpis
        kpi_data = fetch_kpis()  # your cron function should return a KPI instance or similar
        return kpi_data.monthly_reporter_stats.total_reporters
    except AttributeError as e:
        logger.error(
            "KPI object missing expected attribute: %s", e, exc_info=True
        )
        raise ValueError("Invalid KPI data structure") from e
    except Exception as e:
        logger.exception("Unexpected error fetching monthly reporters: %s", e)
        raise


def validate(data, data_type):
    """
    Validates the given data based on the specified data type.

    Args:
        data: The data to be validated.
        data_type: The type of data to validate (e.g., "ip", "url", "hash").

    Returns:
        True if the data is valid for the specified data type, False otherwise.
    """
    validator_methods = {
        "ip": IPHandler().validate_ip,
        "url": DomainHandler().validate_domain,
        "hash": HashHandler().validate_hash
    }

    validator = validator_methods.get(data_type)

    if validator is not None:
        return validator(data)

    raise ValueError(f"Invalid data type: {data_type}. Valid data types are 'ip', 'url', 'hash'.")


@register.filter(name="decode_email_subject")
def decode_email_subject(subject: Optional[str]) -> str:
    """
    Decode an RFC 2047‑encoded email subject, replacing undecodable bytes,
    truncating if too long, and logging errors.

    Usage:
        {{ subject_header|decode_email_subject }}

    Args:
        subject: the raw Subject header string (may be None).

    Returns:
        Decoded, safe string up to MAX_SUBJECT_LENGTH characters, with ellipsis if truncated.
    """
    if not subject:
        return ""

    try:
        parts = []
        for fragment, encoding in decode_header(subject):
            if isinstance(fragment, bytes):
                charset = encoding or "utf-8"
                parts.append(fragment.decode(charset, errors="replace"))
            else:
                parts.append(fragment)
        decoded = "".join(parts)

        if len(decoded) > MAX_SUBJECT_LENGTH:
            return f"{decoded[:MAX_SUBJECT_LENGTH]}..."  # ellipsis
        return decoded

    except Exception:
        logger.exception("Error decoding email subject: %r", subject)
        return subject  # fallback to raw header

@register.filter(name="truncate_chars")
def truncate_chars(value: Union[str, None], max_length: int = 20) -> str:
    """
    Django template filter: truncates a string to a maximum number of characters,
    appending an ellipsis (…) if it was longer.

    Usage in a template:
        {{ some_text|truncate_chars:30 }}

    Args:
        value:       The string to truncate (None is treated as empty).
        max_length:  Maximum number of characters before truncation; must be non‑negative.

    Returns:
        A safely truncated string; if `value` is None or not a string, returns an empty string.
    """
    if not isinstance(max_length, int) or max_length < 0:
        raise ValueError(f"max_length must be a non‑negative integer, got {max_length!r}")

    text = value or ""
    # Truncator handles word boundaries and adds a unicode ellipsis by default
    return Truncator(text).chars(max_length, truncate="…")

@register.simple_tag(name="footer_text")
def footer_text() -> str:
    """
    Django template tag: returns the configured footer text.

    Usage in a template:
        {% load site_tags %}
        <footer>{% footer_text %}</footer>

    Returns:
        The FOOTER_TEXT environment variable, or 'All rights reserved.' if unset.
    """
    return _FOOTER_TEXT

@register.simple_tag(name="site_link")
def site_link() -> str:
    """
    Django template tag: returns the configured site link.

    Usage in a template:
        {% load site_tags %}
        <a href="{% site_link %}">Visit our site</a>

    Returns:
        The value of the LINK environment variable, or 'https://example.com' if unset.
    """
    return _SITE_LINK

@register.simple_tag(name="suspicious_email")
def suspicious_email() -> str:
    """
    Django template tag: returns the configured ‘suspicious’ support email.

    Usage in template:
        {% load your_tags_module %}
        For issues, contact {% suspicious_email %}.

    Returns:
        The EMAIL_SUSPICIOUS environment variable, or a safe default.
    """
    return SUSPICIOUS_EMAIL

@register.filter(name="month_name")
def month_name(month: str) -> str:
    """
    Django template filter: convert a month number (string or int) into its English name.

    Example:
        {{ some_month|month_name }}

    Parameters:
        month:    The month number as a string or integer.
                E.g. "1", 1, "12", 12

    Returns:
        The full month name ("January"–"December"), or "Invalid month" if out of range or non‑numeric.
    """
    try:
        num = int(month)
    except (TypeError, ValueError):
        return "Invalid month"

    # calendar.month_name[0] is empty, so indexes 1–12 map to January–December
    if 1 <= num <= 12:
        return calendar.month_name[num]
    return "Invalid month"
