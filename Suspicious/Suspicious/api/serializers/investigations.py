from __future__ import annotations

from typing import Any

from rest_framework import serializers

from case_handler.models import Case
from cortex_job.models import AnalyzerReport


API_RESULT_TO_INTERNAL = {
    "SAFE": "Safe",
    "INCONCLUSIVE": "Inconclusive",
    "UNCHALLENGED": "Unchallenged",
    "ALLOW_LISTED": "AllowListed",
    "FAILURE": "Failure",
    "SUSPICIOUS": "Suspicious",
    "DANGEROUS": "Dangerous",
}
INTERNAL_RESULT_TO_API = {internal: api for api, internal in API_RESULT_TO_INTERNAL.items()}

STATUS_TO_API = {
    "To Do": "NEW",
    "On Going": "IN_PROGRESS",
    "Done": "DONE",
    "Challenged": "CHALLENGED",
}

API_STATUS_TO_INTERNAL = {
    "NEW": "To Do",
    "IN_PROGRESS": "On Going",
    "DONE": "Done",
    "CHALLENGED": "Challenged",
}

INVESTIGATION_TYPE_CHOICES = ("FILE", "MAIL", "URL", "IP", "HASH", "UNKNOWN")
INVESTIGATION_RESULT_CHOICES = tuple(API_RESULT_TO_INTERNAL.keys()) + ("UNKNOWN",)
INVESTIGATION_ORDERING_CHOICES = ("-creation_date", "creation_date", "-id", "id", "status", "-status", "result", "-result")


def normalize_result_to_api(value: Any) -> str:
    if value is None:
        return "UNKNOWN"

    normalized = str(value).strip()
    if not normalized:
        return "UNKNOWN"

    if normalized.upper() in API_RESULT_TO_INTERNAL:
        return normalized.upper()

    return INTERNAL_RESULT_TO_API.get(normalized, "UNKNOWN")


def normalize_categories(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]

    return [str(value)]


def get_case_type(obj: Case) -> str:
    file_or_mail = getattr(obj, "fileOrMail", None)
    non_file_iocs = getattr(obj, "nonFileIocs", None)

    if obj.fileOrMail_id and file_or_mail:
        if file_or_mail.file_id:
            return "FILE"
        if file_or_mail.mail_id:
            return "MAIL"

    if obj.nonFileIocs_id and non_file_iocs:
        if non_file_iocs.url_id:
            return "URL"
        if non_file_iocs.ip_id:
            return "IP"
        if non_file_iocs.hash_id:
            return "HASH"

    return "UNKNOWN"


def get_case_info_value(obj: Case) -> str:
    file_or_mail = getattr(obj, "fileOrMail", None)
    non_file_iocs = getattr(obj, "nonFileIocs", None)

    if obj.fileOrMail_id and file_or_mail:
        if file_or_mail.file_id and file_or_mail.file:
            file_field = getattr(file_or_mail.file, "file_path", None)
            file_name = getattr(file_field, "name", None)
            if file_name:
                return str(file_name).split("/")[-1]
            return str(file_or_mail.file_id)

        if file_or_mail.mail_id and file_or_mail.mail:
            return getattr(file_or_mail.mail, "subject", "") or obj.description or ""

    if obj.nonFileIocs_id and non_file_iocs:
        if non_file_iocs.url_id and non_file_iocs.url:
            return getattr(non_file_iocs.url, "address", "") or obj.description or ""
        if non_file_iocs.ip_id and non_file_iocs.ip:
            return getattr(non_file_iocs.ip, "address", "") or obj.description or ""
        if non_file_iocs.hash_id and non_file_iocs.hash:
            return (
                getattr(non_file_iocs.hash, "value", "")
                or obj.description
                or ""
            )

    return obj.description or ""


class InvestigationListQuerySerializer(serializers.Serializer):
    search = serializers.CharField(
        required=False, allow_blank=True, trim_whitespace=True, max_length=255
    )
    status = serializers.ChoiceField(
        choices=("ALL", "NEW", "IN_PROGRESS", "DONE", "CHALLENGED", "UNKNOWN"),
        required=False,
        default="ALL",
    )
    type = serializers.ChoiceField(
        choices=("ALL",) + INVESTIGATION_TYPE_CHOICES,
        required=False,
        default="ALL",
    )
    result = serializers.ChoiceField(
        choices=("ALL",) + INVESTIGATION_RESULT_CHOICES,
        required=False,
        default="ALL",
    )
    from_date = serializers.DateField(required=False, input_formats=["%Y-%m-%d"])
    to_date = serializers.DateField(required=False, input_formats=["%Y-%m-%d"])
    ordering = serializers.ChoiceField(
        choices=INVESTIGATION_ORDERING_CHOICES,
        required=False,
        default="-creation_date",
    )


class InvestigationGlobalEditRequestSerializer(serializers.Serializer):
    score = serializers.FloatField(min_value=0, max_value=10)
    confidence = serializers.FloatField(min_value=0, max_value=100)
    classification = serializers.ChoiceField(choices=tuple(API_RESULT_TO_INTERNAL.keys()))

    def validate_classification(self, value: str) -> str:
        return value.upper()


class InvestigationAnalyzerTargetSerializer(serializers.Serializer):
    kind = serializers.CharField()
    id = serializers.IntegerField(allow_null=True)
    value = serializers.CharField(allow_null=True)


class InvestigationCaseInfosSerializer(serializers.Serializer):
    score = serializers.FloatField(allow_null=True)
    confidence = serializers.FloatField(allow_null=True)
    classification = serializers.CharField()
    score_ai = serializers.FloatField(allow_null=True)
    confidence_ai = serializers.FloatField(allow_null=True)
    classification_ai = serializers.CharField()
    category_ai = serializers.CharField(allow_null=True)


class InvestigationRawSerializer(serializers.Serializer):
    case = serializers.DictField()
    fileOrMail = serializers.DictField(allow_null=True)
    nonFileIocs = serializers.DictField(allow_null=True)
    analyzer_report_ids = serializers.ListField(child=serializers.IntegerField())


class InvestigationAnalyzerReportSerializer(serializers.ModelSerializer):
    analyzer_name = serializers.CharField(source="analyzer.name", read_only=True)
    analyzer_id = serializers.CharField(source="analyzer.analyzer_cortex_id", read_only=True)
    categories = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)

    class Meta:
        model = AnalyzerReport
        fields = [
            "id", "cortex_job_id", "type", "status", "analyzer_name", "analyzer_id",
            "level", "confidence", "score", "category", "categories",
            "report_summary", "report_taxonomy", "target", "created_at",
        ]

    def get_categories(self, obj: AnalyzerReport) -> list[str]:
        return normalize_categories(obj.get_category())

    def get_target(self, obj: AnalyzerReport) -> dict[str, Any]:
        if obj.url_id:
            return {"kind": "URL", "id": obj.url_id, "value": getattr(obj.url, "address", str(obj.url_id))}
        if obj.domain_id:
            return {"kind": "DOMAIN", "id": obj.domain_id, "value": getattr(obj.domain, "value", str(obj.domain_id))}
        if obj.mail_id:
            return {"kind": "MAIL", "id": obj.mail_id, "value": getattr(obj.mail, "address", str(obj.mail_id))}
        if obj.hash_id:
            return {"kind": "HASH", "id": obj.hash_id, "value": getattr(obj.hash, "value", str(obj.hash_id))}
        if obj.file_id:
            file_field = getattr(obj.file, "file_path", None)
            file_name = getattr(file_field, "name", None)
            return {"kind": "FILE", "id": obj.file_id, "value": file_name or str(obj.file_id)}
        if obj.ip_id:
            return {"kind": "IP", "id": obj.ip_id, "value": getattr(obj.ip, "address", str(obj.ip_id))}
        if obj.mail_body_id:
            return {"kind": "MAIL_BODY", "id": obj.mail_body_id, "value": getattr(obj.mail_body, "fuzzy_hash", str(obj.mail_body_id))}
        if obj.mail_header_id:
            return {"kind": "MAIL_HEADER", "id": obj.mail_header_id, "value": getattr(obj.mail_header, "fuzzy_hash", str(obj.mail_header_id))}
        return {"kind": "UNKNOWN", "id": None, "value": None}


class InvestigationRowSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    info = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)
    tests_done = serializers.IntegerField(source="analysis_done", read_only=True)
    type = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField()
    reporter_email = serializers.EmailField(source="reporter.email", read_only=True)
    mail_preview_url = serializers.SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            "id", "reporter_email", "status", "info", "created_at",
            "tests_done", "type", "result", "is_challengeable", "is_challenged",
            "mail_preview_url",
        ]

    def get_mail_preview_url(self, obj: Case):
        """Relative URL to the rendered eml→png preview, or null."""
        file_or_mail = getattr(obj, "fileOrMail", None)
        mail = getattr(file_or_mail, "mail", None) if file_or_mail else None
        if not mail:
            return None
        if not getattr(mail, "preview_object_key", ""):
            return None
        return f"/api/cases/{obj.pk}/mail-preview.png"

    def get_status(self, obj: Case) -> str:
        return STATUS_TO_API.get(obj.status, "UNKNOWN")

    def get_result(self, obj: Case) -> str:
        return normalize_result_to_api(obj.results)

    def get_type(self, obj: Case) -> str:
        return get_case_type(obj)

    def get_info(self, obj: Case) -> str:
        return get_case_info_value(obj)


class InvestigationDetailsSerializer(InvestigationRowSerializer):
    analyzer_reports = serializers.SerializerMethodField()
    case_infos = serializers.SerializerMethodField()
    raw = serializers.SerializerMethodField()
    reporter_note = serializers.SerializerMethodField()

    class Meta(InvestigationRowSerializer.Meta):
        fields = InvestigationRowSerializer.Meta.fields + [
            "analyzer_reports", "case_infos", "raw",
            "challenge_proposed_result", "challenge_reason",
            "reporter_context", "reporter_note", "thehive_alert_id",
        ]

    def get_analyzer_reports(self, obj: Case) -> list[dict[str, Any]]:
        queryset = self.context.get("analyzer_reports_qs")
        if queryset is None:
            return []
        return InvestigationAnalyzerReportSerializer(queryset, many=True).data

    def get_case_infos(self, obj: Case) -> dict[str, Any]:
        return {
            "score": obj.final_score,
            "confidence": obj.final_confidence,
            "classification": normalize_result_to_api(obj.results),
            "score_ai": obj.score_ai,
            "confidence_ai": obj.confidence_ai,
            "classification_ai": normalize_result_to_api(obj.results_ai),
            "category_ai": obj.category_ai,
        }

    def get_reporter_note(self, obj: Case) -> str:
        fom = getattr(obj, "fileOrMail", None)
        mail = getattr(fom, "mail", None) if fom else None
        return getattr(mail, "reporterNote", "") or ""

    def get_raw(self, obj: Case) -> dict[str, Any]:
        analyzer_reports_qs = self.context.get("analyzer_reports_qs", AnalyzerReport.objects.none())
        ids = []
        file_or_mail = None
        non_file_iocs = None
        if hasattr(analyzer_reports_qs, "values_list"):
            ids = analyzer_reports_qs.values_list("id", flat=True)
        else:
            ids = [obj.id for obj in analyzer_reports_qs]
        if obj.fileOrMail_id and obj.fileOrMail:
            file_or_mail = {
                "id": obj.fileOrMail_id,
                "file_id": obj.fileOrMail.file_id,
                "mail_id": obj.fileOrMail.mail_id,
            }

        if obj.nonFileIocs_id and obj.nonFileIocs:
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
                "reporter_email": getattr(obj.reporter, "email", ""),
                "analysis_done": obj.analysis_done,
                "status": obj.status,
                "results": obj.results,
                "final_score": obj.final_score,
                "final_confidence": obj.final_confidence,
                "score": obj.score,
                "confidence": obj.confidence,
                "results_ai": obj.results_ai,
                "score_ai": obj.score_ai,
                "confidence_ai": obj.confidence_ai,
                "category_ai": obj.category_ai,
                "is_challenged": obj.is_challenged,
                "is_challengeable": obj.is_challengeable,
                "challenged_result": obj.challenged_result,
                "creation_date": obj.creation_date,
                "last_update": obj.last_update,
                "last_update_by_id": obj.last_update_by_id,
                "thehive_alert_id": obj.thehive_alert_id,
            },
            "fileOrMail": file_or_mail,
            "nonFileIocs": non_file_iocs,
            "analyzer_report_ids": list(ids),
        }