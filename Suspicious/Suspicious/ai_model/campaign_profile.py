import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class CampaignProfile:
    embedding_version: str
    collection_name: str
    max_tokens: int
    distance_threshold: float
    min_members: int
    neighbours: int
    window_days: int
    trigger_class: str
    allow_list_digest: str


def allow_list_digest() -> str:
    """Short fingerprint of the campaign allow-list, so a changed list is visible in the profile."""
    from settings.models import CampaignDomainAllowList

    values = CampaignDomainAllowList.objects.filter(domain__isnull=False).values_list(
        "domain__value", flat=True
    )
    return hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()[:16]


def current_profile() -> CampaignProfile:
    return CampaignProfile(
        embedding_version="cmp-e1",
        collection_name="suspicious_mails",
        max_tokens=128,
        distance_threshold=0.25,
        min_members=3,
        neighbours=20,
        window_days=15,
        trigger_class="Dangerous",
        allow_list_digest=allow_list_digest(),
    )
