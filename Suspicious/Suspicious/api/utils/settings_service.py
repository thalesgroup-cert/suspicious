from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Model, QuerySet
from rest_framework.exceptions import NotFound, ValidationError

from domain_process.models import Domain
from hash_process.models import Hash
from profiles.models import CISOProfile
from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
    CampaignDomainAllowList,
    DenyListDomain,
    WatcherLegitDomain,
    WatcherMonitoredDomain,
)

User = get_user_model()

# ---------------------------------------------------------------------------
# Return type for all bulk create handlers
# ---------------------------------------------------------------------------

CreateResult = dict[str, list[str]]

_EMPTY_RESULT: CreateResult = {
    "created": [],
    "duplicates": [],
    "watcher_conflicts": [],
}


def _make_result(
    *,
    created: list[str],
    duplicates: list[str],
    watcher_conflicts: list[str],
) -> CreateResult:
    return {
        "created": created,
        "duplicates": duplicates,
        "watcher_conflicts": watcher_conflicts,
    }


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ListSectionConfig:
    section: str
    model: Type[Model]
    value_getter: Callable[[Model], str]
    created_at_attr: str = "creation_date"
    queryset_factory: Callable[[], QuerySet] | None = None
    bulk_create_handler: Callable[[list[str], User], CreateResult] | None = None
    allow_delete: bool = True

    def get_queryset(self) -> QuerySet:
        if self.queryset_factory is not None:
            return self.queryset_factory()
        return self.model.objects.all()


# ---------------------------------------------------------------------------
# Queryset factories (unchanged)
# ---------------------------------------------------------------------------

def _domain_list_queryset(model: Type[Model]) -> QuerySet:
    return model.objects.select_related("domain").order_by("-creation_date")


def _hash_list_queryset() -> QuerySet:
    return AllowListFile.objects.select_related("linked_file_hash").order_by("-creation_date")


def _filetype_queryset() -> QuerySet:
    return AllowListFiletype.objects.order_by("-creation_date")


def _ciso_queryset() -> QuerySet:
    return CISOProfile.objects.select_related("user").order_by("user__username")


def _watcher_legit_queryset() -> QuerySet:
    return WatcherLegitDomain.objects.select_related("domain").order_by("-last_update", "-creation_date")


def _watcher_monitored_queryset() -> QuerySet:
    return WatcherMonitoredDomain.objects.select_related("domain").order_by("-last_update", "-creation_date")


# ---------------------------------------------------------------------------
# Bulk create handlers — all return CreateResult
# ---------------------------------------------------------------------------

def _bulk_create_domain_links(
    *,
    values: list[str],
    user: User,
    through_model: Type[Model],
) -> CreateResult:
    """
    Create domain allowlist/denylist entries with full conflict reporting.

    Buckets:
      watcher_conflicts — value is in WatcherLegitDomain OR WatcherMonitoredDomain
                          (managed by Watcher; user does not need to add manually)
      duplicates        — value already in this editable list for this user
      created           — genuinely new entries
    """
    # ── Pre-fetch sets for O(1) lookups ──────────────────────────────────
    watcher_legit_set = set(
        WatcherLegitDomain.objects.filter(domain__value__in=values)
        .values_list("domain__value", flat=True)
    )
    watcher_monitored_set = set(
        WatcherMonitoredDomain.objects.filter(domain__value__in=values)
        .values_list("domain__value", flat=True)
    )
    watcher_set = watcher_legit_set | watcher_monitored_set

    existing_links = set(
        through_model.objects.filter(domain__value__in=values)
        .values_list("domain__value", flat=True)
    )

    # ── Classify each incoming value ─────────────────────────────────────
    watcher_conflicts: list[str] = []
    duplicates: list[str] = []
    to_create_values: list[str] = []

    for value in values:
        if value in watcher_set:
            watcher_conflicts.append(value)
        elif value in existing_links:
            duplicates.append(value)
        else:
            to_create_values.append(value)

    if not to_create_values:
        return _make_result(
            created=[],
            duplicates=duplicates,
            watcher_conflicts=watcher_conflicts,
        )

    # ── Get-or-create Domain objects for the new values ──────────────────
    domain_map = {
        d.value: d
        for d in Domain.objects.filter(value__in=to_create_values)
    }
    missing = [v for v in to_create_values if v not in domain_map]
    if missing:
        Domain.objects.bulk_create([Domain(value=v) for v in missing])
        domain_map.update(
            {d.value: d for d in Domain.objects.filter(value__in=missing)}
        )

    # ── Bulk create the through-model entries ─────────────────────────────
    new_entries = [
        through_model(domain=domain_map[v], user=user)
        for v in to_create_values
    ]
    through_model.objects.bulk_create(new_entries, ignore_conflicts=True)

    created_ids = list(
        through_model.objects.filter(domain__value__in=to_create_values)
        .values_list("id", flat=True)
    )

    return _make_result(
        created=[str(pk) for pk in created_ids],
        duplicates=duplicates,
        watcher_conflicts=watcher_conflicts,
    )


def _bulk_create_hash_links(values: list[str], user: User) -> CreateResult:
    """
    Create file hash allowlist entries with duplicate reporting.

    No watcher equivalent for hashes — watcher_conflicts is always empty.
    """
    existing_links = set(
        AllowListFile.objects.filter(linked_file_hash__value__in=values)
        .values_list("linked_file_hash__value", flat=True)
    )

    duplicates: list[str] = []
    to_create_values: list[str] = []

    for value in values:
        if value in existing_links:
            duplicates.append(value)
        else:
            to_create_values.append(value)

    if not to_create_values:
        return _make_result(created=[], duplicates=duplicates, watcher_conflicts=[])

    hash_map = {h.value: h for h in Hash.objects.filter(value__in=to_create_values)}
    missing = [v for v in to_create_values if v not in hash_map]
    if missing:
        Hash.objects.bulk_create([Hash(value=v) for v in missing])
        hash_map.update({h.value: h for h in Hash.objects.filter(value__in=missing)})

    new_entries = [
        AllowListFile(linked_file_hash=hash_map[v], user=user)
        for v in to_create_values
    ]
    AllowListFile.objects.bulk_create(new_entries, ignore_conflicts=True)

    created_ids = list(
        AllowListFile.objects.filter(linked_file_hash__value__in=to_create_values)
        .values_list("id", flat=True)
    )

    return _make_result(
        created=[str(pk) for pk in created_ids],
        duplicates=duplicates,
        watcher_conflicts=[],
    )


def _bulk_create_filetypes(values: list[str], user: User) -> CreateResult:
    """
    Create filetype allowlist entries with duplicate reporting.
    """
    existing_values = set(
        AllowListFiletype.objects.filter(filetype__in=values)
        .values_list("filetype", flat=True)
    )

    duplicates: list[str] = []
    to_create_values: list[str] = []

    for value in values:
        if value in existing_values:
            duplicates.append(value)
        else:
            to_create_values.append(value)

    if not to_create_values:
        return _make_result(created=[], duplicates=duplicates, watcher_conflicts=[])

    new_entries = [AllowListFiletype(filetype=v, user=user) for v in to_create_values]
    AllowListFiletype.objects.bulk_create(new_entries, ignore_conflicts=True)

    created_ids = list(
        AllowListFiletype.objects.filter(filetype__in=to_create_values)
        .values_list("id", flat=True)
    )

    return _make_result(
        created=[str(pk) for pk in created_ids],
        duplicates=duplicates,
        watcher_conflicts=[],
    )


# ---------------------------------------------------------------------------
# Section registry
# ---------------------------------------------------------------------------

SETTINGS_LIST_SECTIONS: dict[str, ListSectionConfig] = {
    "domains_allow": ListSectionConfig(
        section="domains_allow",
        model=AllowListDomain,
        queryset_factory=lambda: _domain_list_queryset(AllowListDomain),
        value_getter=lambda obj: obj.domain.value if obj.domain else "",
        bulk_create_handler=lambda values, user: _bulk_create_domain_links(
            values=values,
            user=user,
            through_model=AllowListDomain,
        ),
    ),
    "domains_deny": ListSectionConfig(
        section="domains_deny",
        model=DenyListDomain,
        queryset_factory=lambda: _domain_list_queryset(DenyListDomain),
        value_getter=lambda obj: obj.domain.value if obj.domain else "",
        bulk_create_handler=lambda values, user: _bulk_create_domain_links(
            values=values,
            user=user,
            through_model=DenyListDomain,
        ),
    ),
    "campaign_domains_allow": ListSectionConfig(
        section="campaign_domains_allow",
        model=CampaignDomainAllowList,
        queryset_factory=lambda: _domain_list_queryset(CampaignDomainAllowList),
        value_getter=lambda obj: obj.domain.value if obj.domain else "",
        bulk_create_handler=lambda values, user: _bulk_create_domain_links(
            values=values,
            user=user,
            through_model=CampaignDomainAllowList,
        ),
    ),
    "emails_files_allow": ListSectionConfig(
        section="emails_files_allow",
        model=AllowListFile,
        queryset_factory=_hash_list_queryset,
        value_getter=lambda obj: obj.linked_file_hash.value if obj.linked_file_hash else "",
        bulk_create_handler=_bulk_create_hash_links,
    ),
    "filetypes_allow": ListSectionConfig(
        section="filetypes_allow",
        model=AllowListFiletype,
        queryset_factory=_filetype_queryset,
        value_getter=lambda obj: obj.filetype,
        bulk_create_handler=_bulk_create_filetypes,
    ),
    "watcher_legit_domains": ListSectionConfig(
        section="watcher_legit_domains",
        model=WatcherLegitDomain,
        queryset_factory=_watcher_legit_queryset,
        value_getter=lambda obj: obj.domain.value if obj.domain else "",
        allow_delete=False,
    ),
    "watcher_monitored_domains": ListSectionConfig(
        section="watcher_monitored_domains",
        model=WatcherMonitoredDomain,
        queryset_factory=_watcher_monitored_queryset,
        value_getter=lambda obj: obj.domain.value if obj.domain else "",
        allow_delete=False,
    ),
    "ciso_users": ListSectionConfig(
        section="ciso_users",
        model=CISOProfile,
        queryset_factory=_ciso_queryset,
        value_getter=lambda obj: obj.user.username if obj.user else "",
        allow_delete=False,
    ),
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class SettingsListSectionService:

    @staticmethod
    def get_config(section: str) -> ListSectionConfig:
        try:
            return SETTINGS_LIST_SECTIONS[section]
        except KeyError as exc:
            raise ValidationError({"section": "Invalid section."}) from exc

    @classmethod
    def list_items(cls, section: str) -> list[dict[str, Any]]:
        config = cls.get_config(section)
        return [
            {
                "id": str(obj.id),
                "value": config.value_getter(obj),
                "created_at": getattr(obj, config.created_at_attr, None),
            }
            for obj in config.get_queryset()
        ]

    @classmethod
    @transaction.atomic
    def create_items(
        cls,
        section: str,
        values: list[str],
        user: User,
    ) -> CreateResult:
        """
        Create list entries and return a structured result:

            {
                "created":           [str, ...],   IDs of new entries
                "duplicates":        [str, ...],   values already in this list
                "watcher_conflicts": [str, ...],   values managed by Watcher
            }

        The view passes this dict directly to the frontend so it can show
        distinct messages for each category instead of a single generic notice.
        """
        config = cls.get_config(section)

        if config.bulk_create_handler is None:
            raise ValidationError({"section": "This section does not support creation."})

        return config.bulk_create_handler(values, user)

    @classmethod
    def delete_item(cls, section: str, item_id: str) -> str:
        config = cls.get_config(section)

        if not config.allow_delete:
            raise ValidationError({"section": "This section does not support deletion."})

        deleted, _ = config.model.objects.filter(id=item_id).delete()
        if deleted == 0:
            raise NotFound("Not found.")

        return str(item_id)
