# api/services/settings_sections.py
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


@dataclass(frozen=True)
class ListSectionConfig:
    section: str
    model: Type[Model]
    value_getter: Callable[[Model], str]
    created_at_attr: str = "creation_date"
    queryset_factory: Callable[[], QuerySet] | None = None
    bulk_create_handler: Callable[[list[str], User], list[str]] | None = None
    allow_delete: bool = True

    def get_queryset(self) -> QuerySet:
        if self.queryset_factory is not None:
            return self.queryset_factory()
        return self.model.objects.all()


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


def _bulk_create_domain_links(
    *,
    values: list[str],
    user: User,
    through_model: Type[Model],
) -> list[str]:
    domain_map = {
        domain.value: domain
        for domain in Domain.objects.filter(value__in=values)
    }

    missing_values = [value for value in values if value not in domain_map]
    if missing_values:
        Domain.objects.bulk_create([Domain(value=value) for value in missing_values])
        domain_map.update(
            {domain.value: domain for domain in Domain.objects.filter(value__in=missing_values)}
        )

    existing_links = set(
        through_model.objects.filter(
            domain__value__in=values,
            user=user,
        ).values_list("domain__value", flat=True)
    )

    to_create = [
        through_model(domain=domain_map[value], user=user)
        for value in values
        if value not in existing_links
    ]

    if to_create:
        through_model.objects.bulk_create(to_create)

    created_ids = list(
        through_model.objects.filter(
            domain__value__in=values,
            user=user,
        ).values_list("id", flat=True)
    )
    return [str(pk) for pk in created_ids]


def _bulk_create_hash_links(values: list[str], user: User) -> list[str]:
    hash_map = {
        obj.value: obj
        for obj in Hash.objects.filter(value__in=values)
    }

    missing_values = [value for value in values if value not in hash_map]
    if missing_values:
        Hash.objects.bulk_create([Hash(value=value) for value in missing_values])
        hash_map.update(
            {obj.value: obj for obj in Hash.objects.filter(value__in=missing_values)}
        )

    existing_links = set(
        AllowListFile.objects.filter(
            linked_file_hash__value__in=values,
            user=user,
        ).values_list("linked_file_hash__value", flat=True)
    )

    to_create = [
        AllowListFile(linked_file_hash=hash_map[value], user=user)
        for value in values
        if value not in existing_links
    ]

    if to_create:
        AllowListFile.objects.bulk_create(to_create)

    created_ids = list(
        AllowListFile.objects.filter(
            linked_file_hash__value__in=values,
            user=user,
        ).values_list("id", flat=True)
    )
    return [str(pk) for pk in created_ids]


def _bulk_create_filetypes(values: list[str], user: User) -> list[str]:
    existing_values = set(
        AllowListFiletype.objects.filter(
            filetype__in=values,
            user=user,
        ).values_list("filetype", flat=True)
    )

    to_create = [
        AllowListFiletype(filetype=value, user=user)
        for value in values
        if value not in existing_values
    ]

    if to_create:
        AllowListFiletype.objects.bulk_create(to_create)

    created_ids = list(
        AllowListFiletype.objects.filter(
            filetype__in=values,
            user=user,
        ).values_list("id", flat=True)
    )
    return [str(pk) for pk in created_ids]


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
        queryset = config.get_queryset()

        return [
            {
                "id": str(obj.id),
                "value": config.value_getter(obj),
                "created_at": getattr(obj, config.created_at_attr, None),
            }
            for obj in queryset
        ]

    @classmethod
    @transaction.atomic
    def create_items(cls, section: str, values: list[str], user: User) -> list[str]:
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