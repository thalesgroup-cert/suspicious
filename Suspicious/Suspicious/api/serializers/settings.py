from rest_framework import serializers

from settings.models import (
    EmailFeederState,
    Mailbox,
)
from profiles.models import CISOProfile
from cortex_job.models import Analyzer

class SettingsListItemSerializer(serializers.Serializer):
    id = serializers.CharField()
    value = serializers.CharField()
    created_at = serializers.DateTimeField()


class EmailFeederStateSerializer(serializers.ModelSerializer):
    enabled = serializers.BooleanField(source="is_running")

    class Meta:
        model = EmailFeederState
        fields = ["enabled", "updated_at"]


class AnalyzerSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Analyzer
        fields = ["id", "name", "weight", "analyzer_cortex_id", "is_active"]


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