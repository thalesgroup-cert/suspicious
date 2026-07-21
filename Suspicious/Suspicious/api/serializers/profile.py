import re
from rest_framework import serializers
from profiles.models import UserProfile, CISOProfile, Theme, DEFAULT_SEMANTIC_COLORS
from profiles.profiles_utils.avatar_storage import presigned_avatar_url


# ---------------------------------------------------------------------------
# Hex color validator
# ---------------------------------------------------------------------------

HEX_RE = re.compile(r'^#[0-9A-Fa-f]{6}$')

def _validate_hex(value: str, field_path: str) -> str:
    """Raise ValidationError if value is not a valid 6-digit hex color."""
    if not isinstance(value, str) or not HEX_RE.match(value):
        raise serializers.ValidationError(
            {field_path: f"Must be a 6-digit hex color (e.g. #3B82F6). Got: {value!r}"}
        )
    return value.upper()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

RESULT_KEYS = {"safe", "suspicious", "dangerous", "inconclusive"}
STATUS_KEYS = {"done", "in_progress", "new", "failure", "challenged", "unknown"}


class SemanticColorsField(serializers.JSONField):
    """
    Custom field that validates and normalises semantic_colors payloads.
    """

    def to_internal_value(self, data):
        data = super().to_internal_value(data)

        if not isinstance(data, dict):
            raise serializers.ValidationError("semantic_colors must be an object.")

        import copy
        result_out = copy.deepcopy(DEFAULT_SEMANTIC_COLORS)

        for group, keys in (("result", RESULT_KEYS), ("status", STATUS_KEYS)):
            incoming = data.get(group, {})
            if not isinstance(incoming, dict):
                raise serializers.ValidationError(
                    f"semantic_colors.{group} must be an object."
                )
            for key in keys:
                if key in incoming:
                    entry = incoming[key]
                    if not isinstance(entry, dict):
                        raise serializers.ValidationError(
                            f"semantic_colors.{group}.{key} must be an object."
                        )
                    main = entry.get("main")
                    if main is not None:
                        _validate_hex(main, f"semantic_colors.{group}.{key}.main")
                        result_out[group][key]["main"] = main.upper()

        return result_out


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

ALLOWED_AVATAR_STYLES = {
    "bottts", "identicon", "initials", "avataaars",
    "funEmoji", "thumbs", "shapes", "notionists",
}

MAX_AVATAR_OPTION_KEYS = 20
MAX_AVATAR_OPTION_KEY_LEN = 32
MAX_AVATAR_OPTION_VALUE_LEN = 64
MAX_AVATAR_OPTION_LIST_ITEMS = 20
MAX_AVATAR_OPTIONS_BYTES = 2048


def _validate_avatar_options(options):
    """Bounded/loose validation of the DiceBear options blob.

    Accepts a dict of category -> (str | list[str]); normalises scalars to
    one-element lists. Enforces size caps only; DiceBear ignores unknown
    keys and the avatar renders solely in the owner's browser, so caps are
    the only real safeguard needed.
    """
    import json

    if not isinstance(options, dict):
        raise serializers.ValidationError("avatar.options must be an object.")
    if len(options) > MAX_AVATAR_OPTION_KEYS:
        raise serializers.ValidationError(
            f"avatar.options may have at most {MAX_AVATAR_OPTION_KEYS} keys."
        )
    clean = {}
    for key, value in options.items():
        if not isinstance(key, str) or not (1 <= len(key) <= MAX_AVATAR_OPTION_KEY_LEN):
            raise serializers.ValidationError(
                f"avatar.options key must be a string of length "
                f"1..{MAX_AVATAR_OPTION_KEY_LEN}. Got: {key!r}"
            )
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list):
            items = value
        else:
            raise serializers.ValidationError(
                f"avatar.options.{key} must be a string or list of strings."
            )
        if len(items) > MAX_AVATAR_OPTION_LIST_ITEMS:
            raise serializers.ValidationError(
                f"avatar.options.{key} may have at most "
                f"{MAX_AVATAR_OPTION_LIST_ITEMS} items."
            )
        for item in items:
            if not isinstance(item, str) or not (1 <= len(item) <= MAX_AVATAR_OPTION_VALUE_LEN):
                raise serializers.ValidationError(
                    f"avatar.options.{key} values must be strings of length "
                    f"1..{MAX_AVATAR_OPTION_VALUE_LEN}."
                )
        clean[key] = items
    if len(json.dumps(clean)) > MAX_AVATAR_OPTIONS_BYTES:
        raise serializers.ValidationError(
            f"avatar.options is too large (max {MAX_AVATAR_OPTIONS_BYTES} bytes)."
        )
    return clean


class AvatarField(serializers.JSONField):
    """Validates a DiceBear avatar config: {} or {style, seed}."""

    def to_internal_value(self, data):
        data = super().to_internal_value(data)

        if not isinstance(data, dict):
            raise serializers.ValidationError("avatar must be an object.")

        if not data:
            return {}

        style = data.get("style")
        seed = data.get("seed")

        if style == "upload":
            raise serializers.ValidationError(
                "avatar.style 'upload' can only be set via "
                "POST /profile/avatar/upload/."
            )

        if style not in ALLOWED_AVATAR_STYLES:
            raise serializers.ValidationError(
                f"avatar.style must be one of {sorted(ALLOWED_AVATAR_STYLES)}. Got: {style!r}"
            )
        if not isinstance(seed, str) or not (1 <= len(seed) <= 64):
            raise serializers.ValidationError(
                "avatar.seed must be a string of length 1..64."
            )

        result = {"style": style, "seed": seed}
        options = data.get("options")
        if options:
            result["options"] = _validate_avatar_options(options)
        return result


# ---------------------------------------------------------------------------
# Profile serializers
# ---------------------------------------------------------------------------

class UserProfileSerializer(serializers.ModelSerializer):
    semantic_colors = SemanticColorsField(required=False)
    avatar = AvatarField(required=False)

    class Meta:
        model = UserProfile
        fields = [
            "id",
            "function",
            "gbu",
            "country",
            "region",
            "wants_acknowledgement",
            "wants_results",
            "theme",
            "auto_seasonal",
            "semantic_colors",
            "avatar",
            "tour_completed",
            "creation_date",
            "last_update",
        ]
        read_only_fields = ["id", "creation_date", "last_update"]

    def validate_theme(self, value):
        valid = {choice[0] for choice in Theme.choices}
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid theme '{value}'. Valid choices: {sorted(valid)}"
            )
        return value

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep["semantic_colors"] = instance.get_semantic_colors()
        avatar = rep.get("avatar") or {}
        if avatar.get("style") == "upload" and avatar.get("seed"):
            url = presigned_avatar_url(avatar["seed"])
            if url:
                rep["avatar"] = {**avatar, "url": url}
        return rep


class CISOProfileSerializer(serializers.ModelSerializer):
    semantic_colors = SemanticColorsField(required=False)
    avatar = AvatarField(required=False)

    class Meta:
        model = CISOProfile
        fields = [
            "id",
            "function",
            "gbu",
            "country",
            "region",
            "scope",
            "wants_acknowledgement",
            "wants_results",
            "theme",
            "auto_seasonal",
            "semantic_colors",
            "avatar",
            "tour_completed",
            "creation_date",
            "last_update",
        ]
        read_only_fields = ["id", "scope", "creation_date", "last_update"]

    def validate_theme(self, value):
        valid = {choice[0] for choice in Theme.choices}
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid theme '{value}'. Valid choices: {sorted(valid)}"
            )
        return value

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep["semantic_colors"] = instance.get_semantic_colors()
        avatar = rep.get("avatar") or {}
        if avatar.get("style") == "upload" and avatar.get("seed"):
            url = presigned_avatar_url(avatar["seed"])
            if url:
                rep["avatar"] = {**avatar, "url": url}
        return rep


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class AppearanceSerializer(serializers.Serializer):
    """PATCH /profile/appearance/ — theme + seasonal flag + colors."""
    theme         = serializers.ChoiceField(
        choices=Theme.choices, required=False
    )
    auto_seasonal = serializers.BooleanField(required=False)
    semantic_colors = SemanticColorsField(required=False)
    avatar = AvatarField(required=False)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save(update_fields=list(validated_data.keys()) + ["last_update"])
        return instance


class PreferencesSerializer(serializers.Serializer):
    """PATCH /profile/preferences/ — notification preferences."""
    wants_acknowledgement = serializers.BooleanField(required=False)
    wants_results         = serializers.BooleanField(required=False)
    tour_completed        = serializers.BooleanField(required=False)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save(update_fields=list(validated_data.keys()) + ["last_update"])
        return instance


class SemanticColorsSerializer(serializers.Serializer):
    """
    PATCH /profile/colors/ — colors-only endpoint.
    Lets the frontend sync color changes without touching theme or preferences.
    """
    semantic_colors = SemanticColorsField(required=True)

    def update(self, instance, validated_data):
        instance.semantic_colors = validated_data["semantic_colors"]
        instance.save(update_fields=["semantic_colors", "last_update"])
        return instance