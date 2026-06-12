from rest_framework import serializers


class ConfigFieldSerializer(serializers.Serializer):
    key = serializers.CharField()
    type = serializers.CharField()
    required = serializers.BooleanField()
    default = serializers.JSONField(allow_null=True)
    help = serializers.CharField(allow_blank=True)


class ScheduleSerializer(serializers.Serializer):
    name = serializers.CharField()
    interval_seconds = serializers.IntegerField()


class ConnectorSerializer(serializers.Serializer):
    """Read-only view assembled from manifest + ConnectorState."""
    name = serializers.CharField()
    version = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    author = serializers.CharField(allow_blank=True)
    docs_url = serializers.CharField(allow_blank=True)
    events = serializers.ListField(child=serializers.CharField())
    schedules = ScheduleSerializer(many=True)
    config_schema = ConfigFieldSerializer(many=True)
    enabled = serializers.BooleanField()
    enabled_by_default = serializers.BooleanField()
    last_health_ok = serializers.BooleanField(allow_null=True)
    last_health_detail = serializers.CharField(allow_blank=True)
    last_health_at = serializers.DateTimeField(allow_null=True)


class ConnectorDeliverySerializer(serializers.Serializer):
    id = serializers.IntegerField()
    event = serializers.CharField()
    case_id = serializers.IntegerField(allow_null=True)
    status = serializers.CharField()
    error = serializers.CharField(allow_blank=True)
    duration_ms = serializers.IntegerField()
    attempt = serializers.IntegerField()
    created_at = serializers.DateTimeField()
