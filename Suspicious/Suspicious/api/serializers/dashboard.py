from rest_framework import serializers
from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats,
)


class DashboardSummaryQuerySerializer(serializers.Serializer):
    month = serializers.IntegerField(min_value=1, max_value=12)
    year = serializers.IntegerField(min_value=1)
    scope = serializers.CharField(
        required=False,
        default="ALL",
        allow_blank=False,
        trim_whitespace=True,
        max_length=64,
    )


class DashboardPrefixSerializer(serializers.Serializer):
    label = serializers.CharField()
    value = serializers.IntegerField(min_value=0)


class DashboardKpisSerializer(serializers.Serializer):
    new_users = serializers.IntegerField(min_value=0)
    total_reporters = serializers.IntegerField(min_value=0)
    total_cases = serializers.IntegerField(min_value=0)


class DashboardDangerCountsSerializer(serializers.Serializer):
    failure = serializers.IntegerField(min_value=0)
    safe = serializers.IntegerField(min_value=0)
    inconclusive = serializers.IntegerField(min_value=0)
    suspicious = serializers.IntegerField(min_value=0)
    dangerous = serializers.IntegerField(min_value=0)
    malicious = serializers.IntegerField(min_value=0)


class DashboardSummaryResponseSerializer(serializers.Serializer):
    month = serializers.IntegerField(min_value=1, max_value=12)
    year = serializers.IntegerField(min_value=1)
    scope = serializers.CharField()
    kpis = DashboardKpisSerializer()
    danger_counts = DashboardDangerCountsSerializer()
    top_prefixes = DashboardPrefixSerializer(many=True)


class MonthlyCasesSummaryAggregateSerializer(serializers.Serializer):
    month = serializers.IntegerField(min_value=1, max_value=12)
    year = serializers.IntegerField(min_value=1)
    suspicious_cases = serializers.IntegerField(min_value=0)
    inconclusive_cases = serializers.IntegerField(min_value=0)
    failure_cases = serializers.IntegerField(min_value=0)
    dangerous_cases = serializers.IntegerField(min_value=0)
    safe_cases = serializers.IntegerField(min_value=0)
    challenged_cases = serializers.IntegerField(min_value=0)
    allow_listed_cases = serializers.IntegerField(min_value=0)
    uncategorized_cases = serializers.IntegerField(min_value=0)
    spam_cases = serializers.IntegerField(min_value=0)
    newsletter_cases = serializers.IntegerField(min_value=0)
    classic_phishing_cases = serializers.IntegerField(min_value=0)
    clone_cases = serializers.IntegerField(min_value=0)
    blackmail_cases = serializers.IntegerField(min_value=0)
    whaling_cases = serializers.IntegerField(min_value=0)
    internal_cases = serializers.IntegerField(min_value=0)
    external_cases = serializers.IntegerField(min_value=0)


class UserCasesMonthlyStatsAggregateRowSerializer(serializers.Serializer):
    username = serializers.CharField()
    month = serializers.IntegerField(min_value=1, max_value=12)
    year = serializers.IntegerField(min_value=1)
    total_cases = serializers.IntegerField(min_value=0)
    total_safe = serializers.IntegerField(min_value=0)
    total_dangerous = serializers.IntegerField(min_value=0)
    total_suspicious = serializers.IntegerField(min_value=0)
    total_inconclusive = serializers.IntegerField(min_value=0)
    total_failure = serializers.IntegerField(min_value=0)
    total_uncategorized = serializers.IntegerField(min_value=0)
    total_spam = serializers.IntegerField(min_value=0)
    total_newsletter = serializers.IntegerField(min_value=0)
    total_classic_phishing = serializers.IntegerField(min_value=0)
    total_clone = serializers.IntegerField(min_value=0)
    total_blackmail = serializers.IntegerField(min_value=0)
    total_whaling = serializers.IntegerField(min_value=0)
    total_internal = serializers.IntegerField(min_value=0)
    total_external = serializers.IntegerField(min_value=0)
    total_challenged = serializers.IntegerField(min_value=0)
    total_allow_listed = serializers.IntegerField(min_value=0)


class MonthlyCasesSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyCasesSummary
        fields = "__all__"


class MonthlyReporterStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyReporterStats
        fields = "__all__"


class TotalCasesStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TotalCasesStats
        fields = "__all__"


class UserCasesMonthlyStatsSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = UserCasesMonthlyStats
        fields = "__all__"

class TopPrefixItemSerializer(serializers.Serializer):
    prefix = serializers.CharField()
    total = serializers.IntegerField()
    safe = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    dangerous = serializers.IntegerField()
    failure = serializers.IntegerField()
    inconclusive = serializers.IntegerField()


class TopPrefixesResponseSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["user", "group"])
    month = serializers.CharField(allow_null=True, required=False)
    year = serializers.CharField(allow_null=True, required=False)
    data = TopPrefixItemSerializer(many=True)