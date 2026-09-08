"""CISO scope helpers.

A CISOProfile.scope is a pipe-delimited list of org-unit group names
(e.g. "EMEA|FR"), the literal "ALL", or unset ("Not defined" / "").
A case belongs to a scope when its reporter is in one of those groups —
the same rule dashboard.update_group_monthly_stats uses.
"""
from __future__ import annotations


def clean_scope(value) -> str | None:
    """Normalise a raw scope value. Returns None when effectively unset."""
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized or normalized.lower() == "not defined":
        return None
    return normalized


def parse_scope_groups(scope: str | None):
    """Group names a scope resolves to.

    Returns None for "ALL" (meaning: no restriction), a list of group
    names otherwise (possibly empty).
    """
    cleaned = clean_scope(scope)
    if cleaned is None:
        return []
    if cleaned.upper() == "ALL":
        return None
    return [part.strip() for part in cleaned.split("|") if part.strip()]


def scoped_case_queryset(queryset, user):
    """Restrict a Case queryset to what ``user`` may see.

    CERT/Admin and non-CISO users: unrestricted.
    CISO with scope "ALL": unrestricted.
    CISO with a real scope: cases whose reporter is in a scope group.
    CISO with an unset scope: nothing (the UI prompts them to set one).
    """
    from profiles.models import CISOProfile

    if user.groups.filter(name__in=["CERT", "Admin"]).exists():
        return queryset
    try:
        ciso_profile = user.cisoprofile
    except CISOProfile.DoesNotExist:
        return queryset

    groups = parse_scope_groups(ciso_profile.scope)
    if groups is None:
        return queryset
    if not groups:
        return queryset.none()
    return queryset.filter(reporter__groups__name__in=groups).distinct()
