from __future__ import annotations

from typing import Any, Dict, Tuple, Type

from django.contrib.auth import get_user_model
from profiles.models import UserProfile, CISOProfile

User = get_user_model()


class ProfileService:
    USER_DEFAULTS: Dict[str, Any] = {
        "function": "",
        "gbu": "",
        "country": "",
        "region": "",
    }

    CISO_DEFAULTS: Dict[str, Any] = {
        **USER_DEFAULTS,
        "scope": "Not defined",
    }

    @classmethod
    def is_ciso(cls, user: User) -> bool:
        return user.groups.filter(name="CISO").exists()

    @classmethod
    def get_profile_model_and_defaults(
        cls, user: User
    ) -> Tuple[Type[UserProfile] | Type[CISOProfile], Dict[str, Any]]:
        if cls.is_ciso(user):
            return CISOProfile, cls.CISO_DEFAULTS
        return UserProfile, cls.USER_DEFAULTS

    @classmethod
    def get_or_create_profile(cls, user: User) -> UserProfile | CISOProfile:
        model, defaults = cls.get_profile_model_and_defaults(user)
        profile, _ = model.objects.get_or_create(user=user, defaults=defaults)
        return profile

    @classmethod
    def apply_updates(
        cls,
        profile: UserProfile | CISOProfile,
        updates: dict[str, Any],
    ) -> list[str]:
        changed_fields: list[str] = []

        for field, value in updates.items():
            if getattr(profile, field) != value:
                setattr(profile, field, value)
                changed_fields.append(field)

        return changed_fields