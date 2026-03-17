# api/serializers/settings.py
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

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
        fields = ["id", "name", "weight", "analyzer_cortex_id", "is_active"]


class AnalyzerWeightUpdateSerializer(serializers.Serializer):
    weight = serializers.DecimalField(
        max_digits=3,
        decimal_places=1,
        min_value=Decimal("0.0"),
        max_value=Decimal("1.0"),
    )

    def validate_weight(self, value: Decimal) -> Decimal:
        # Preserve frontend behavior: slider uses 0.1 increments.
        return value.quantize(Decimal("0.1"))


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