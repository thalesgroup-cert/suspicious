from rest_framework import serializers

class HomeMonthlySerializer(serializers.Serializer):
    everyone_items = serializers.IntegerField()
    scope_items = serializers.IntegerField()
    scope_name = serializers.CharField(allow_null=True, required=False)


class HomeDangerCountsSerializer(serializers.Serializer):
    safe = serializers.IntegerField()
    inconclusive = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    dangerous = serializers.IntegerField()


class HomeSuggestedScopesSerializer(serializers.Serializer):
    region = serializers.CharField(allow_null=True, required=False)
    country = serializers.CharField(allow_null=True, required=False)
    gbu = serializers.CharField(allow_null=True, required=False)


class HomeSpotlightSerializer(serializers.Serializer):
    title = serializers.CharField()
    description = serializers.CharField()
    cta_label = serializers.CharField()
    cta_path = serializers.CharField()


class HomeSummaryResponseSerializer(serializers.Serializer):
    show_scope_modal = serializers.BooleanField()
    monthly = HomeMonthlySerializer()
    danger_counts = HomeDangerCountsSerializer()
    scope_danger_counts = HomeDangerCountsSerializer(allow_null=True)
    suggested_scopes = HomeSuggestedScopesSerializer()
    spotlight = HomeSpotlightSerializer()