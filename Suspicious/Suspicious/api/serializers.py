from rest_framework import serializers
from .models import (
    Kpi, MonthlyCasesSummary, MonthlyReporterStats,
    TotalCasesStats, UserCasesMonthlyStats
)


class KpiSerializer(serializers.ModelSerializer):
    class Meta:
        model = Kpi
        fields = '__all__'


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
    class Meta:
        model = UserCasesMonthlyStats
        fields = '__all__'
