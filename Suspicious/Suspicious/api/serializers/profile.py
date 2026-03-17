from rest_framework import serializers
from profiles.models import Theme


class ProfileSerializer(serializers.Serializer):
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField()


class PreferencesPatchSerializer(serializers.Serializer):
    wants_acknowledgement = serializers.BooleanField(required=False)
    wants_results = serializers.BooleanField(required=False)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError(
                "At least one preference field must be provided."
            )
        return attrs


class PreferencesResponseSerializer(serializers.Serializer):
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()


class AppearancePatchSerializer(serializers.Serializer):
    theme = serializers.ChoiceField(choices=Theme.choices, required=False)
    auto_seasonal = serializers.BooleanField(required=False)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError(
                "At least one appearance field must be provided."
            )
        return attrs


class AppearanceResponseSerializer(serializers.Serializer):
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField()
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()