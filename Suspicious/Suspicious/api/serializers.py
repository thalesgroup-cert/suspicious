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
