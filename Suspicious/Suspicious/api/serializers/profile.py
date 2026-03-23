# profiles/serializers.py
import re
from rest_framework import serializers
from profiles.models import UserProfile, CISOProfile, Theme, DEFAULT_SEMANTIC_COLORS


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
# Semantic color field
#
# Validates the full nested structure:
#   {
#     result: { safe, suspicious, dangerous, inconclusive },
#     status: { done, in_progress, new, failure, challenged, unknown },
#   }
#
# Any missing keys are filled from DEFAULT_SEMANTIC_COLORS so partial
# updates are safe. Extra keys are silently dropped.
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
# Profile serializers
# ---------------------------------------------------------------------------

class UserProfileSerializer(serializers.ModelSerializer):
    semantic_colors = SemanticColorsField(required=False)

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
        # Always return the merged (complete) color structure, not the raw stored value.
        rep["semantic_colors"] = instance.get_semantic_colors()
        return rep


class CISOProfileSerializer(serializers.ModelSerializer):
    semantic_colors = SemanticColorsField(required=False)

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
        return rep


# ---------------------------------------------------------------------------
# Partial-update serializers
# Used by dedicated PATCH endpoints so clients don't have to send the
# full profile every time they change a single field.
# ---------------------------------------------------------------------------

class AppearanceSerializer(serializers.Serializer):
    """PATCH /profile/appearance/ — theme + seasonal flag + colors."""
    theme         = serializers.ChoiceField(
        choices=Theme.choices, required=False
    )
    auto_seasonal = serializers.BooleanField(required=False)
    semantic_colors = SemanticColorsField(required=False)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save(update_fields=list(validated_data.keys()) + ["last_update"])
        return instance


class PreferencesSerializer(serializers.Serializer):
    """PATCH /profile/preferences/ — notification preferences."""
    wants_acknowledgement = serializers.BooleanField(required=False)
    wants_results         = serializers.BooleanField(required=False)

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