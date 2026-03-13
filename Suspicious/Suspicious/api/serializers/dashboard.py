from rest_framework import serializers
from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats
)


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
