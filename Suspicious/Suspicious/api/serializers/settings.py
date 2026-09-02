from __future__ import annotations

from decimal import Decimal

from rest_framework import serializers

from settings.models import EmailFeederState, Mailbox
from profiles.models import CISOProfile
from cortex_job.models import Analyzer


class SettingsListItemSerializer(serializers.Serializer):
    id = serializers.CharField()
    value = serializers.CharField()
    created_at = serializers.DateTimeField()


class SettingsListBulkCreateSerializer(serializers.Serializer):
    values = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False,
    )

    def validate_values(self, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()

        for raw in values:
            value = str(raw).strip()
            if not value:
                continue
            if value in seen:
                continue
            seen.add(value)
            cleaned.append(value)

        if not cleaned:
            raise serializers.ValidationError("No valid values provided.")

        return cleaned


class EmailFeederStateSerializer(serializers.ModelSerializer):
    enabled = serializers.BooleanField(source="is_running")

    class Meta:
        model = EmailFeederState
        fields = ["enabled", "updated_at"]


class EmailFeederStateUpdateSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()


class AnalyzerSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Analyzer
        fields = ["id", "name", "weight", "tier", "analyzer_cortex_id", "is_active"]


class AnalyzerUpdateSerializer(serializers.Serializer):
    weight = serializers.DecimalField(
        max_digits=3,
        decimal_places=1,
        min_value=Decimal("0.0"),
        max_value=Decimal("1.0"),
        required=False,
    )
    tier = serializers.IntegerField(min_value=1, max_value=3, required=False)

    def validate_weight(self, value: Decimal) -> Decimal:
        return value.quantize(Decimal("0.1"))

    def validate(self, attrs):
        if "weight" not in attrs and "tier" not in attrs:
            raise serializers.ValidationError("Provide 'weight' and/or 'tier'.")
        return attrs


class MailboxSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mailbox
        fields = [
            "id",
            "name",
            "username",
            "server",
            "port",
            "creation_date",
            "last_update",
        ]


class CISOUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = CISOProfile
        fields = [
            "id",
            "username",
            "email",
            "function",
            "gbu",
            "country",
            "region",
            "scope",
            "creation_date",
            "last_update",
        ]

class WatcherDomainListItemSerializer(serializers.Serializer):
    id = serializers.CharField()
    value = serializers.CharField()
    created_at = serializers.DateTimeField()