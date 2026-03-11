from rest_framework import serializers
from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats
)
from django.db.models import Q
from profiles.models import UserProfile, CISOProfile, Theme
from case_handler.models import Case
from cortex_job.models import AnalyzerReport

class SubmissionAnalyzerReportSerializer(serializers.ModelSerializer):
    analyzer_name = serializers.CharField(source="analyzer.name", read_only=True)
    analyzer_id = serializers.CharField(source="analyzer.analyzer_cortex_id", read_only=True)
    categories = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)

    class Meta:
        model = AnalyzerReport
        fields = [
            "id",
            "cortex_job_id",
            "type",
            "status",
            "analyzer_name",
            "analyzer_id",
            "level",
            "confidence",
            "score",
            "category",
            "categories",
            "report_summary",
            "report_taxonomy",
            "report_full",
            "target",
            "created_at",
        ]

    def get_categories(self, obj):
        return obj.get_category()

    def get_target(self, obj):
        if obj.url_id:
            return {
                "kind": "url",
                "id": obj.url_id,
                "value": getattr(obj.url, "address", str(obj.url_id)),
            }
        if obj.domain_id:
            return {
                "kind": "domain",
                "id": obj.domain_id,
                "value": getattr(obj.domain, "domain_name", str(obj.domain_id)),
            }
        if obj.mail_id:
            return {
                "kind": "mail",
                "id": obj.mail_id,
                "value": getattr(obj.mail, "address", str(obj.mail_id)),
            }
        if obj.hash_id:
            return {
                "kind": "hash",
                "id": obj.hash_id,
                "value": getattr(obj.hash, "value", str(obj.hash_id)),
            }
        if obj.file_id:
            try:
                file_name = obj.file.file_path.name
            except Exception:
                file_name = str(obj.file_id)
            return {
                "kind": "file",
                "id": obj.file_id,
                "value": file_name,
            }
        if obj.ip_id:
            return {
                "kind": "ip",
                "id": obj.ip_id,
                "value": getattr(obj.ip, "address", str(obj.ip_id)),
            }
        if obj.mail_body_id:
            return {
                "kind": "mail_body",
                "id": obj.mail_body_id,
                "value": getattr(obj.mail_body, "fuzzy_hash", str(obj.mail_body_id)),
            }
        if obj.mail_header_id:
            return {
                "kind": "mail_header",
                "id": obj.mail_header_id,
                "value": getattr(obj.mail_header, "fuzzy_hash", str(obj.mail_header_id)),
            }
        return {"kind": "unknown", "id": None, "value": None}


class SubmissionRowSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    artifact = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date")
    tests_done = serializers.IntegerField(source="analysis_done")
    type = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            "id",
            "status",
            "artifact",
            "created_at",
            "tests_done",
            "type",
            "result",
            "is_challengeable",
            "is_challenged",
        ]

    def get_status(self, obj):
        mapping = {
            "To Do": "NEW",
            "On Going": "IN_PROGRESS",
            "Done": "DONE",
            "Challenged": "CHALLENGED",
        }
        return mapping.get(obj.status, "UNKNOWN")

    def get_result(self, obj):
        mapping = {
            "Safe": "SAFE",
            "Inconclusive": "INCONCLUSIVE",
            "Unchallenged": "UNCHALLENGED",
            "AllowListed": "ALLOW_LISTED",
            "Failure": "FAILURE",
            "Suspicious": "SUSPICIOUS",
            "Dangerous": "DANGEROUS",
        }
        return mapping.get(obj.results, "UNKNOWN")

    def get_type(self, obj):
        if obj.fileOrMail_id:
            linked = obj.fileOrMail
            if linked.file_id:
                return "FILE"
            if linked.mail_id:
                return "MAIL"

        if obj.nonFileIocs_id:
            linked = obj.nonFileIocs
            if linked.url_id:
                return "URL"
            if linked.ip_id:
                return "IP"
            if linked.hash_id:
                return "HASH"

        return "UNKNOWN"

    def get_artifact(self, obj):
        if obj.fileOrMail_id:
            linked = obj.fileOrMail
            if linked:
                if linked.file_id and linked.file:
                    try:
                        return linked.file.file_path.name.split("/")[-1]
                    except Exception:
                        return getattr(linked.file, "filename", "") or str(linked.file_id)
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
                    return (
                        getattr(linked.hash, "value", "")
                        or getattr(linked.hash, "hash", "")
                        or str(linked.hash)
                    )

        return obj.description or ""


class SubmissionDetailsSerializer(SubmissionRowSerializer):
    analyzer_reports = serializers.SerializerMethodField()
    raw = serializers.SerializerMethodField()

    class Meta(SubmissionRowSerializer.Meta):
        fields = SubmissionRowSerializer.Meta.fields + ["analyzer_reports", "raw"]

    def get_analyzer_reports(self, obj):
        queryset = self.context.get("analyzer_reports_qs")
        if queryset is None:
            return []
        return SubmissionAnalyzerReportSerializer(queryset, many=True).data

    def get_raw(self, obj):
        file_or_mail = None
        non_file_iocs = None

        if obj.fileOrMail_id:
            file_or_mail = {
                "id": obj.fileOrMail_id,
                "file_id": obj.fileOrMail.file_id,
                "mail_id": obj.fileOrMail.mail_id,
            }

        if obj.nonFileIocs_id:
            non_file_iocs = {
                "id": obj.nonFileIocs_id,
                "url_id": obj.nonFileIocs.url_id,
                "ip_id": obj.nonFileIocs.ip_id,
                "hash_id": obj.nonFileIocs.hash_id,
            }

        return {
            "case": {
                "id": obj.id,
                "description": obj.description,
                "reporter_id": obj.reporter_id,
                "analysis_done": obj.analysis_done,
                "status": obj.status,
                "results": obj.results,
                "finalScore": obj.finalScore,
                "finalConfidence": obj.finalConfidence,
                "score": obj.score,
                "confidence": obj.confidence,
                "resultsAI": obj.resultsAI,
                "scoreAI": obj.scoreAI,
                "confidenceAI": obj.confidenceAI,
                "categoryAI": obj.categoryAI,
                "is_challenged": obj.is_challenged,
                "is_challengeable": obj.is_challengeable,
                "challenged_result": obj.challenged_result,
                "creation_date": obj.creation_date,
                "last_update": obj.last_update,
                "last_update_by_id": obj.last_update_by_id,
            },
            "fileOrMail": file_or_mail,
            "nonFileIocs": non_file_iocs,
            "analyzer_report_ids": list(
                self.context.get("analyzer_reports_qs", AnalyzerReport.objects.none()).values_list("id", flat=True)
            ),
        }

class SubmissionListSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)
    tests_done = serializers.IntegerField(source="analysis_done", read_only=True)
    result = serializers.CharField(source="results", read_only=True)
    type = serializers.SerializerMethodField()
    artifact = serializers.SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            "id",
            "status",
            "artifact",
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

    def get_artifact(self, obj):
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