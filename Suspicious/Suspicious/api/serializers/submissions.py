import os

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from case_handler.models import Case
from cortex_job.models import AnalyzerReport

from api.submissions.constants import (
    ANALYZER_TARGET_KIND_CHOICES,
    RESULT_MAP,
    STATUS_MAP,
    SUBMISSION_RESULT_CHOICES,
    SUBMISSION_STATUS_CHOICES,
    SUBMISSION_TYPE_CHOICES,
)
from api.permissions.submissions import user_has_submission_elevated_access


def _normalize_whitespace(value: str) -> str:
    return " ".join((value or "").split()).strip()


def _to_upper_snake(value: str) -> str:
    return _normalize_whitespace(value).replace("-", " ").replace("/", " ").upper().replace(" ", "_")


def normalize_case_status(raw_status: str) -> str:
    normalized = _normalize_whitespace(raw_status).lower()
    if not normalized:
        return "UNKNOWN"
    return STATUS_MAP.get(normalized, _to_upper_snake(normalized))


def normalize_case_result(raw_result: str) -> str:
    if not raw_result:
        return "UNKNOWN"
    return RESULT_MAP.get(raw_result, _to_upper_snake(raw_result))


def resolve_case_type(obj: Case) -> str:
    linked_file_or_mail = getattr(obj, "fileOrMail", None)
    linked_non_file_iocs = getattr(obj, "nonFileIocs", None)

    if obj.fileOrMail_id and linked_file_or_mail is not None:
        if linked_file_or_mail.file_id:
            return "FILE"
        if linked_file_or_mail.mail_id:
            return "MAIL"

    if obj.nonFileIocs_id and linked_non_file_iocs is not None:
        if linked_non_file_iocs.url_id:
            return "URL"
        if linked_non_file_iocs.ip_id:
            return "IP"
        if linked_non_file_iocs.hash_id:
            return "HASH"

    return "UNKNOWN"


def resolve_case_artifact(obj: Case) -> str:
    linked_file_or_mail = getattr(obj, "fileOrMail", None)
    linked_non_file_iocs = getattr(obj, "nonFileIocs", None)

    if obj.fileOrMail_id and linked_file_or_mail is not None:
        if linked_file_or_mail.file_id and getattr(linked_file_or_mail, "file", None):
            file_obj = linked_file_or_mail.file
            file_path = getattr(getattr(file_obj, "file_path", None), "name", "")
            if file_path:
                return os.path.basename(file_path)
            return getattr(file_obj, "filename", "") or str(linked_file_or_mail.file_id)

        if linked_file_or_mail.mail_id and getattr(linked_file_or_mail, "mail", None):
            return getattr(linked_file_or_mail.mail, "subject", "") or ""

    if obj.nonFileIocs_id and linked_non_file_iocs is not None:
        if linked_non_file_iocs.url_id and getattr(linked_non_file_iocs, "url", None):
            return getattr(linked_non_file_iocs.url, "address", "") or str(linked_non_file_iocs.url_id)

        if linked_non_file_iocs.ip_id and getattr(linked_non_file_iocs, "ip", None):
            return getattr(linked_non_file_iocs.ip, "address", "") or str(linked_non_file_iocs.ip_id)

        if linked_non_file_iocs.hash_id and getattr(linked_non_file_iocs, "hash", None):
            hash_obj = linked_non_file_iocs.hash
            return (
                getattr(hash_obj, "value", "")
                or getattr(hash_obj, "hash", "")
                or str(linked_non_file_iocs.hash_id)
            )

    return obj.description or ""


def resolve_analyzer_report_target(obj: AnalyzerReport) -> dict:
    if obj.url_id:
        return {
            "kind": "URL",
            "id": obj.url_id,
            "value": getattr(obj.url, "address", str(obj.url_id)),
        }
    if obj.domain_id:
        return {
            "kind": "DOMAIN",
            "id": obj.domain_id,
            # Domain model stores the domain string in the `value` field — NOT domain_name.
            # Using domain_name caused domain artifacts to fall back to the integer PK id.
            "value": getattr(obj.domain, "value", str(obj.domain_id)),
        }
    if obj.mail_id:
        return {
            "kind": "MAIL",
            "id": obj.mail_id,
            "value": getattr(obj.mail, "address", str(obj.mail_id)),
        }
    if obj.hash_id:
        return {
            "kind": "HASH",
            "id": obj.hash_id,
            "value": getattr(obj.hash, "value", str(obj.hash_id)),
        }
    if obj.file_id:
        file_path = getattr(getattr(obj.file, "file_path", None), "name", "")
        return {
            "kind": "FILE",
            "id": obj.file_id,
            "value": os.path.basename(file_path) if file_path else str(obj.file_id),
        }
    if obj.ip_id:
        return {
            "kind": "IP",
            "id": obj.ip_id,
            "value": getattr(obj.ip, "address", str(obj.ip_id)),
        }
    if obj.mail_body_id:
        return {
            "kind": "MAIL_BODY",
            "id": obj.mail_body_id,
            "value": getattr(obj.mail_body, "fuzzy_hash", str(obj.mail_body_id)),
        }
    if obj.mail_header_id:
        return {
            "kind": "MAIL_HEADER",
            "id": obj.mail_header_id,
            "value": getattr(obj.mail_header, "fuzzy_hash", str(obj.mail_header_id)),
        }

    return {"kind": "UNKNOWN", "id": None, "value": None}


class AnalyzerReportTargetSerializer(serializers.Serializer):
    kind = serializers.ChoiceField(choices=ANALYZER_TARGET_KIND_CHOICES, read_only=True)
    id = serializers.IntegerField(allow_null=True, read_only=True)
    value = serializers.CharField(allow_null=True, read_only=True)


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

    @extend_schema_field(AnalyzerReportTargetSerializer)
    def get_target(self, obj):
        return resolve_analyzer_report_target(obj)


class BaseSubmissionSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    artifact = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)
    tests_done = serializers.IntegerField(source="analysis_done", read_only=True)
    type = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField()
    mail_preview_url = serializers.SerializerMethodField()

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
            "mail_preview_url",
        ]

    @extend_schema_field(serializers.CharField(allow_null=True, read_only=True))
    def get_mail_preview_url(self, obj):
        """Relative URL to the rendered eml→png preview, or null."""
        file_or_mail = getattr(obj, "fileOrMail", None)
        mail = getattr(file_or_mail, "mail", None) if file_or_mail else None
        if not mail:
            return None
        preview = getattr(mail, "preview_png", None)
        if not preview or not getattr(preview, "name", ""):
            return None
        return f"/api/cases/{obj.pk}/mail-preview.png"

    @extend_schema_field(serializers.ChoiceField(choices=SUBMISSION_STATUS_CHOICES, read_only=True))
    def get_status(self, obj):
        return normalize_case_status(obj.status)

    @extend_schema_field(serializers.ChoiceField(choices=SUBMISSION_RESULT_CHOICES, read_only=True))
    def get_result(self, obj):
        return normalize_case_result(obj.results)

    @extend_schema_field(serializers.ChoiceField(choices=SUBMISSION_TYPE_CHOICES, read_only=True))
    def get_type(self, obj):
        return resolve_case_type(obj)

    @extend_schema_field(serializers.CharField(read_only=True))
    def get_artifact(self, obj):
        return resolve_case_artifact(obj)


class SubmissionListSerializer(BaseSubmissionSerializer):
    class Meta(BaseSubmissionSerializer.Meta):
        fields = BaseSubmissionSerializer.Meta.fields + [
            "is_challengeable",
            "is_challenged",
        ]


class SubmissionRowSerializer(BaseSubmissionSerializer):
    class Meta(BaseSubmissionSerializer.Meta):
        fields = BaseSubmissionSerializer.Meta.fields + [
            "is_challengeable",
            "is_challenged",
        ]


class SubmissionDetailsSerializer(SubmissionRowSerializer):
    analyzer_reports = serializers.SerializerMethodField()

    class Meta(SubmissionRowSerializer.Meta):
        fields = SubmissionRowSerializer.Meta.fields + [
            "analyzer_reports",
        ]

    def get_analyzer_reports(self, obj):
        reports = self.context.get("analyzer_reports", [])
        return SubmissionAnalyzerReportSerializer(reports, many=True).data


class AdminSubmissionDetailsSerializer(SubmissionDetailsSerializer):
    raw = serializers.SerializerMethodField()

    class Meta(SubmissionDetailsSerializer.Meta):
        fields = SubmissionDetailsSerializer.Meta.fields + ["raw"]

    def get_raw(self, obj):
        request = self.context.get("request")
        if not request or not user_has_submission_elevated_access(request.user):
            return None

        file_or_mail = None
        non_file_iocs = None
        analyzer_reports = self.context.get("analyzer_reports", [])

        linked_file_or_mail = getattr(obj, "fileOrMail", None)
        linked_non_file_iocs = getattr(obj, "nonFileIocs", None)

        if obj.fileOrMail_id and linked_file_or_mail is not None:
            file_or_mail = {
                "id": obj.fileOrMail_id,
                "file_id": linked_file_or_mail.file_id,
                "mail_id": linked_file_or_mail.mail_id,
            }

        if obj.nonFileIocs_id and linked_non_file_iocs is not None:
            non_file_iocs = {
                "id": obj.nonFileIocs_id,
                "url_id": linked_non_file_iocs.url_id,
                "ip_id": linked_non_file_iocs.ip_id,
                "hash_id": linked_non_file_iocs.hash_id,
            }

        return {
            "case": {
                "id": obj.id,
                "description": obj.description,
                "reporter_id": obj.reporter_id,
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
            },
            "fileOrMail": file_or_mail,
            "nonFileIocs": non_file_iocs,
            "analyzer_report_ids": [report.id for report in analyzer_reports],
        }