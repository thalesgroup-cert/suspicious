from rest_framework import serializers
from profiles.models import Theme



class ProfileSerializer(serializers.Serializer):
    function = serializers.CharField(allow_blank=True, required=False)
    gbu = serializers.CharField(allow_blank=True, required=False)
    country = serializers.CharField(allow_blank=True, required=False)
    region = serializers.CharField(allow_blank=True, required=False)
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField()


class UpdatePreferencesSerializer(serializers.Serializer):
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()


class UpdateAppearanceSerializer(serializers.Serializer):
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField(required=False)