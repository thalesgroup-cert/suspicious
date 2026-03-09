from rest_framework import serializers
from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats
)

class MonthlyCasesSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyCasesSummary
        fields = '__all__'

class MonthlyReporterStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyReporterStats
        fields = '__all__'

class TotalCasesStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TotalCasesStats
        fields = '__all__'

class UserCasesMonthlyStatsSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = UserCasesMonthlyStats
        fields = '__all__'

class DashboardPrefixSerializer(serializers.Serializer):
    label = serializers.CharField()
    value = serializers.IntegerField()


class DashboardKpisSerializer(serializers.Serializer):
    new_users = serializers.IntegerField()
    total_reporters = serializers.IntegerField()
    total_cases = serializers.IntegerField()


class DashboardDangerCountsSerializer(serializers.Serializer):
    failure = serializers.IntegerField()
    safe = serializers.IntegerField()
    inconclusive = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    dangerous = serializers.IntegerField()
    malicious = serializers.IntegerField()


class DashboardSummaryResponseSerializer(serializers.Serializer):
    month = serializers.IntegerField()
    year = serializers.IntegerField()
    scope = serializers.CharField()
    kpis = DashboardKpisSerializer()
    danger_counts = DashboardDangerCountsSerializer()
    top_prefixes = DashboardPrefixSerializer(many=True)

class CampaignClassificationCountsSerializer(serializers.Serializer):
    SAFE = serializers.IntegerField()
    UNWANTED = serializers.IntegerField()
    DANGEROUS = serializers.IntegerField()


class CampaignPcaPointSerializer(serializers.Serializer):
    x = serializers.FloatField()
    y = serializers.FloatField()
    label = serializers.CharField()
    suspicious_case_id = serializers.CharField(allow_null=True, required=False)
    sourceRefs = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
    )


class CampaignPcaResponseSerializer(serializers.Serializer):
    points = CampaignPcaPointSerializer(many=True)
    explained_variance = serializers.ListField(
        child=serializers.FloatField(),
        min_length=2,
        max_length=2,
    )


class CampaignMailVolumeBandSerializer(serializers.Serializer):
    name = serializers.CharField()
    start = serializers.CharField()
    end = serializers.CharField()


class CampaignMailVolumeResponseSerializer(serializers.Serializer):
    dates = serializers.ListField(child=serializers.CharField())
    non_danger = serializers.ListField(child=serializers.IntegerField())
    dangerous = serializers.ListField(child=serializers.IntegerField())
    campaigns = CampaignMailVolumeBandSerializer(many=True)