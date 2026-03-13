from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, NotFound, ValidationError
from django.db.models import Q
from case_handler.models import Case
from cortex_job.models import AnalyzerReport
from api.serializers.investigations import InvestigationRowSerializer, InvestigationDetailsSerializer

def user_is_investigator(user):
    return user.groups.filter(name__in=["CERT", "CISO", "Admin"]).exists()


class InvestigationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not user_is_investigator(request.user):
            raise PermissionDenied("Not authorized.")

        queryset = (
            Case.objects
            .select_related(
                "reporter",
                "fileOrMail",
                "fileOrMail__file",
                "fileOrMail__mail",
                "nonFileIocs",
                "nonFileIocs__url",
                "nonFileIocs__ip",
                "nonFileIocs__hash",
            )
            .order_by("-creation_date")
        )

        serializer = InvestigationRowSerializer(queryset, many=True)
        return Response({"items": serializer.data})

class InvestigationDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, request, case_id: int):
        if not user_is_investigator(request.user):
            raise PermissionDenied("Not authorized.")

        try:
            obj = (
                Case.objects
                .select_related(
                    "reporter",
                    "last_update_by",
                    "fileOrMail",
                    "fileOrMail__file",
                    "fileOrMail__mail",
                    "nonFileIocs",
                    "nonFileIocs__url",
                    "nonFileIocs__ip",
                    "nonFileIocs__hash",
                )
                .get(pk=case_id)
            )
        except Case.DoesNotExist:
            raise NotFound("Investigation not found.")

        return obj

    def _get_analyzer_reports_queryset(self, obj: Case):
        q = Q()

        if obj.fileOrMail_id and obj.fileOrMail:
            if obj.fileOrMail.file_id:
                q |= Q(file_id=obj.fileOrMail.file_id)
            if obj.fileOrMail.mail_id:
                q |= Q(mail_id=obj.fileOrMail.mail_id)

        if obj.nonFileIocs_id and obj.nonFileIocs:
            if obj.nonFileIocs.url_id:
                q |= Q(url_id=obj.nonFileIocs.url_id)
            if obj.nonFileIocs.ip_id:
                q |= Q(ip_id=obj.nonFileIocs.ip_id)
            if obj.nonFileIocs.hash_id:
                q |= Q(hash_id=obj.nonFileIocs.hash_id)

        if not q:
            return AnalyzerReport.objects.none()

        return (
            AnalyzerReport.objects
            .filter(q)
            .select_related(
                "analyzer",
                "url",
                "domain",
                "mail",
                "hash",
                "file",
                "ip",
                "mail_body",
                "mail_header",
            )
            .order_by("-creation_date")
            .distinct()
        )

    def get(self, request, case_id: int):
        obj = self.get_object(request, case_id)
        analyzer_reports_qs = self._get_analyzer_reports_queryset(obj)

        serializer = InvestigationDetailsSerializer(
            obj,
            context={
                "request": request,
                "analyzer_reports_qs": analyzer_reports_qs,
            },
        )
        return Response(serializer.data)

class InvestigationGlobalEditView(APIView):
    permission_classes = [IsAuthenticated]
    def _get_analyzer_reports_queryset(self, obj: Case):
        q = Q()

        if obj.fileOrMail_id and obj.fileOrMail:
            if obj.fileOrMail.file_id:
                q |= Q(file_id=obj.fileOrMail.file_id)
            if obj.fileOrMail.mail_id:
                q |= Q(mail_id=obj.fileOrMail.mail_id)

        if obj.nonFileIocs_id and obj.nonFileIocs:
            if obj.nonFileIocs.url_id:
                q |= Q(url_id=obj.nonFileIocs.url_id)
            if obj.nonFileIocs.ip_id:
                q |= Q(ip_id=obj.nonFileIocs.ip_id)
            if obj.nonFileIocs.hash_id:
                q |= Q(hash_id=obj.nonFileIocs.hash_id)

        if not q:
            return AnalyzerReport.objects.none()

        return (
            AnalyzerReport.objects
            .filter(q)
            .select_related(
                "analyzer",
                "url",
                "domain",
                "mail",
                "hash",
                "file",
                "ip",
                "mail_body",
                "mail_header",
            )
            .order_by("-creation_date")
            .distinct()
        )
    def patch(self, request, case_id: int):
        if not user_is_investigator(request.user):
            raise PermissionDenied("Not authorized.")

        try:
            obj = Case.objects.get(pk=case_id)
        except Case.DoesNotExist:
            raise NotFound("Case not found.")

        score = request.data.get("score")
        confidence = request.data.get("confidence")
        classification = request.data.get("classification")

        if score is None or confidence is None or not classification:
            raise ValidationError("score, confidence and classification are required.")

        try:
            score = float(score)
            confidence = float(confidence)
        except (TypeError, ValueError):
            raise ValidationError("score and confidence must be numeric.")

        if score < 0 or score > 10:
            raise ValidationError({"score": "Must be between 0 and 10."})

        if confidence < 0 or confidence > 100:
            raise ValidationError({"confidence": "Must be between 0 and 100."})

        allowed = {
            "SAFE": "Safe",
            "INCONCLUSIVE": "Inconclusive",
            "UNCHALLENGED": "Unchallenged",
            "ALLOW_LISTED": "AllowListed",
            "FAILURE": "Failure",
            "SUSPICIOUS": "Suspicious",
            "DANGEROUS": "Dangerous",
        }

        classification_value = allowed.get(str(classification).upper())
        if not classification_value:
            raise ValidationError({"classification": "Invalid classification."})

        obj.finalScore = score
        obj.finalConfidence = confidence
        obj.results = classification_value
        obj.last_update_by = request.user
        obj.save(
            update_fields=[
                "finalScore",
                "finalConfidence",
                "results",
                "last_update_by",
                "last_update",
            ]
        )

        analyzer_reports_qs = self._get_analyzer_reports_queryset(obj)  # déplacer cette méthode dans un mixin/base si besoin
        serializer = InvestigationDetailsSerializer(
            obj,
            context={
                "request": request,
                "analyzer_reports_qs": analyzer_reports_qs,
            },
        )
        return Response(serializer.data)