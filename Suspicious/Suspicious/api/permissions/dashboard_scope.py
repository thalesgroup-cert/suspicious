"""Server-side dashboard scope resolution.

Scope keys: ``ALL``, ``OWN_COUNTRY``, ``OWN_SCOPE`` (CISO profile scope),
``COUNTRY:<CC>``, ``REGION:<NAME>``. Reporters carry Django groups named
after their country code and region (profiles_utils/ldap.py), so a scope
resolves to the group names a case's reporter must all belong to.

- every user: ``ALL``, and ``OWN_COUNTRY`` when their profile has a country
  backed by the Django group of that name (profile fields are read-only in
  the API, the group check is defence in depth);
- CISO: also ``OWN_SCOPE`` (their CISOProfile scope; their own stored scope
  string, e.g. ``AU`` or ``AU | Off GBU``, is accepted as an alias);
- CERT/Admin/superuser: also any ``COUNTRY:`` / ``REGION:``.
Anything else raises PermissionDenied (403), never data.
"""
from typing import NamedTuple

from rest_framework.exceptions import PermissionDenied

from profiles.models import CISOProfile, UserProfile
from profiles.profiles_utils.scope import clean_scope, parse_scope_groups

ELEVATED_GROUPS = {"CERT", "Admin"}


class Scope(NamedTuple):
    key: str
    label: str
    groups: list[str] | None  # None = Overall


OVERALL = Scope("ALL", "Overall", None)


def is_elevated(user) -> bool:
    return user.is_superuser or user.groups.filter(name__in=ELEVATED_GROUPS).exists()


def _own_country(user) -> str | None:
    """Profile country, trusted only when backed by the LDAP-set group of that name."""
    for model in (UserProfile, CISOProfile):
        country = clean_scope(model.objects.filter(user=user).values_list("country", flat=True).first())
        if country:
            return country if user.groups.filter(name=country).exists() else None
    return None


def _ciso_scope(user) -> Scope | None:
    if not user.groups.filter(name="CISO").exists():
        return None
    raw = CISOProfile.objects.filter(user=user).values_list("scope", flat=True).first()
    groups = parse_scope_groups(raw)
    if not groups:  # None ("ALL") is plain Overall; [] is unset
        return None
    return Scope("OWN_SCOPE", " | ".join(groups), groups)


def may_see_names(user, scope: Scope) -> bool:
    """Reporter names: CERT/Admin/superuser anywhere, a CISO only inside their own scope."""
    return is_elevated(user) or scope.key == "OWN_SCOPE"


def scope_options(user) -> tuple[str, list[Scope]]:
    """(default key, scopes the caller may use)."""
    elevated = is_elevated(user)
    country = _own_country(user)
    ciso = _ciso_scope(user)
    options = []
    if country:
        options.append(Scope("OWN_COUNTRY", f"My country ({country})", [country]))
    if ciso:
        options.append(ciso)
    options.append(OVERALL)
    if elevated:
        options += [Scope(f"COUNTRY:{c}", c, [c]) for c in _distinct("country")]
        options += [Scope(f"REGION:{r}", r, [r]) for r in _distinct("region")]
    if ciso and not elevated:
        default = ciso.key
    elif country:
        default = "OWN_COUNTRY"
    else:
        default = "ALL"
    return default, options


def _distinct(field):
    """Values actually present on user profiles."""
    values = UserProfile.objects.order_by(field).values_list(field, flat=True).distinct()
    return [v for v in values if clean_scope(v)]


def resolve_scope(user, requested: str | None) -> Scope:
    if not requested:
        requested, _ = scope_options(user)
    requested = requested.strip()
    if requested == "ALL":
        return OVERALL
    if requested == "OWN_COUNTRY":
        country = _own_country(user)
        if country:
            return Scope(requested, f"My country ({country})", [country])
    # The CISO's own stored scope string ("AU", "AU|Off GBU", "AU | Off GBU")
    # is an alias of OWN_SCOPE (the pre-Task-2 UI sends it). Compared after the
    # same split/strip, against the caller's own scope only.
    ciso = _ciso_scope(user)
    if ciso and (requested == "OWN_SCOPE" or parse_scope_groups(requested) == ciso.groups):
        return ciso
    kind, _, value = requested.partition(":")
    value = value.strip()
    if kind in ("COUNTRY", "REGION") and value:
        if is_elevated(user) or (kind == "COUNTRY" and value == _own_country(user)):
            return Scope(requested, value, [value])
    raise PermissionDenied("This dashboard scope is not available to you.")
