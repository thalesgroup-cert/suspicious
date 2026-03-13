from rest_framework import serializers
from cortex_job.models import AnalyzerReport
from case_handler.models import Case

class InvestigationAnalyzerReportSerializer(serializers.ModelSerializer):
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
                value = obj.file.file_path.name
            except Exception:
                value = str(obj.file_id)
            return {
                "kind": "file",
                "id": obj.file_id,
                "value": value,
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


class InvestigationRowSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    info = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(source="creation_date", read_only=True)
    tests_done = serializers.IntegerField(source="analysis_done", read_only=True)
    type = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField()
    reporter_email = serializers.EmailField(source="reporter.email", read_only=True)

    class Meta:
        model = Case
        fields = [
            "id",
            "reporter_email",
            "status",
            "info",
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
        if obj.fileOrMail_id and obj.fileOrMail:
            if obj.fileOrMail.file_id:
                return "FILE"
            if obj.fileOrMail.mail_id:
                return "MAIL"

        if obj.nonFileIocs_id and obj.nonFileIocs:
            if obj.nonFileIocs.url_id:
                return "URL"
            if obj.nonFileIocs.ip_id:
                return "IP"
            if obj.nonFileIocs.hash_id:
                return "HASH"

        return "UNKNOWN"

    def get_info(self, obj):
        if obj.fileOrMail_id and obj.fileOrMail:
            if obj.fileOrMail.file_id and obj.fileOrMail.file:
                try:
                    return obj.fileOrMail.file.file_path.name.split("/")[-1]
                except Exception:
                    return str(obj.fileOrMail.file_id)
            if obj.fileOrMail.mail_id and obj.fileOrMail.mail:
                return getattr(obj.fileOrMail.mail, "subject", "") or obj.description or ""

        if obj.nonFileIocs_id and obj.nonFileIocs:
            if obj.nonFileIocs.url_id and obj.nonFileIocs.url:
                return getattr(obj.nonFileIocs.url, "address", "") or obj.description or ""
            if obj.nonFileIocs.ip_id and obj.nonFileIocs.ip:
                return getattr(obj.nonFileIocs.ip, "address", "") or obj.description or ""
            if obj.nonFileIocs.hash_id and obj.nonFileIocs.hash:
                return (
                    getattr(obj.nonFileIocs.hash, "value", "")
                    or getattr(obj.nonFileIocs.hash, "hash", "")
                    or obj.description
                    or ""
                )

        return obj.description or ""


class InvestigationDetailsSerializer(InvestigationRowSerializer):
    analyzer_reports = serializers.SerializerMethodField()
    case_infos = serializers.SerializerMethodField()
    raw = serializers.SerializerMethodField()

    class Meta(InvestigationRowSerializer.Meta):
        fields = InvestigationRowSerializer.Meta.fields + [
            "analyzer_reports",
            "case_infos",
            "raw",
        ]

    def get_analyzer_reports(self, obj):
        queryset = self.context.get("analyzer_reports_qs")
        if queryset is None:
            return []
        return InvestigationAnalyzerReportSerializer(queryset, many=True).data

    def get_case_infos(self, obj):
        return {
            "score": obj.finalScore,
            "confidence": obj.finalConfidence,
            "classification": obj.results,
            "score_ai": obj.scoreAI,
            "confidence_ai": obj.confidenceAI,
            "classification_ai": obj.resultsAI,
            "category_ai": obj.categoryAI,
        }

    def get_raw(self, obj):
        file_or_mail = None
        non_file_iocs = None

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