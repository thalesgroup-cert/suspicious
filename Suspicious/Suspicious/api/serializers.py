from rest_framework import serializers
from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats
)
from profiles.models import UserProfile, CISOProfile, Theme
from case_handler.models import Case


class SubmissionListSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)
    tests_done = serializers.IntegerField(source="analysis_done", read_only=True)
    result = serializers.CharField(source="results", read_only=True)
    type = serializers.SerializerMethodField()
    info = serializers.SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            "id",
            "status",
            "info",
            "created_at",
            "tests_done",
            "type",
            "result",
        ]

    def get_type(self, obj):
        if obj.fileOrMail_id:
            linked = obj.fileOrMail
            if linked:
                if linked.mail_id:
                    return "mail"
                if linked.file_id:
                    return "file"

        if obj.nonFileIocs_id:
            linked = obj.nonFileIocs
            if linked:
                if linked.url_id:
                    return "url"
                if linked.ip_id:
                    return "ip"
                if linked.hash_id:
                    return "hash"

        return "case"

    def get_info(self, obj):
        if obj.fileOrMail_id:
            linked = obj.fileOrMail
            if linked:
                if linked.file_id and linked.file:
                    return linked.file.file_path.name.split("/")[-1] or getattr(linked.file, "filename", "") or ""
                if linked.mail_id and linked.mail:
                    return getattr(linked.mail, "subject", "") or ""

        if obj.nonFileIocs_id:
            linked = obj.nonFileIocs
            if linked:
                if linked.url_id and linked.url:
                    return getattr(linked.url, "address", "") or str(linked.url)
                if linked.ip_id and linked.ip:
                    return getattr(linked.ip, "address", "") or str(linked.ip)
                if linked.hash_id and linked.hash:
                    return getattr(linked.hash, "value", "") or getattr(linked.hash, "hash", "") or str(linked.hash)

        return obj.description or ""

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
    

class ProfileSerializer(serializers.Serializer):
    function = serializers.CharField(allow_blank=True, required=False)
    gbu = serializers.CharField(allow_blank=True, required=False)
    country = serializers.CharField(allow_blank=True, required=False)
    region = serializers.CharField(allow_blank=True, required=False)
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField()


class UpdatePreferencesSerializer(serializers.Serializer):
    wants_acknowledgement = serializers.BooleanField()
    wants_results = serializers.BooleanField()


class UpdateAppearanceSerializer(serializers.Serializer):
    theme = serializers.ChoiceField(choices=Theme.choices)
    auto_seasonal = serializers.BooleanField(required=False)
    
    
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