"""CISO scope helpers.

A CISOProfile.scope is a pipe-delimited list of org-unit group names
(e.g. "EMEA|Off GBU"), the literal "ALL", or unset ("Not defined" / "").
Each name is a different org dimension (region / country / GBU), so
multiple names are AND-ed: a case is in scope when its reporter is in
*every* selected group. A Romanian Off-GBU reporter carries
{RO, EMEA, Off GBU}, so "RO|Off GBU" narrows to that reporter — it does
not union everyone in RO with everyone in Off GBU.
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
    # AND across dimensions: chained .filter() on a reverse M2M requires the
    # reporter to be in *all* of the named groups.
    for name in groups:
        queryset = queryset.filter(reporter__groups__name=name)
    return queryset.distinct()
