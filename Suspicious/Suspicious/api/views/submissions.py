from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, NotFound, ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.pagination import PageNumberPagination
from case_handler.models import Case
from cortex_job.models import AnalyzerReport
from api.serializers.submissions import SubmissionRowSerializer, SubmissionDetailsSerializer, SubmissionListSerializer
from django.db.models import Q

class SubmissionPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class MySubmissionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = (
            Case.objects
            .filter(reporter=request.user)
            .select_related("fileOrMail", "nonFileIocs")
            .order_by("-creation_date")
        )

        items = SubmissionRowSerializer(queryset, many=True).data
        return Response({"items": items})

class SubmissionDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, request, submission_id: int):
        try:
            obj = (
                Case.objects
                .select_related(
                    "fileOrMail",
                    "fileOrMail__file",
                    "fileOrMail__mail",
                    "nonFileIocs",
                    "nonFileIocs__url",
                    "nonFileIocs__ip",
                    "nonFileIocs__hash",
                    "reporter",
                    "last_update_by",
                )
                .get(pk=submission_id)
            )
        except Case.DoesNotExist:
            raise NotFound("Submission not found.")

        is_owner = obj.reporter_id == request.user.id
        is_elevated = request.user.groups.filter(name__in=["CERT", "CISO", "Admin"]).exists()

        if not is_owner and not is_elevated:
            raise PermissionDenied("Not authorized.")

        return obj

    def _get_analyzer_reports_queryset(self, obj: Case):
        q = Q()

        if obj.fileOrMail_id and obj.fileOrMail:
            if obj.fileOrMail.file_id:
                q |= Q(file_id=obj.fileOrMail.file_id)

            # mail support is partial here because AnalyzerReport points to MailAddress / MailBody / MailHeader,
            # while Case points to Mail. If later you expose Mail -> body/header/address relations,
            # you can extend this block.

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

    def get(self, request, submission_id: int):
        obj = self.get_object(request, submission_id)
        analyzer_reports_qs = self._get_analyzer_reports_queryset(obj)

        serializer = SubmissionDetailsSerializer(
            obj,
            context={
                "request": request,
                "analyzer_reports_qs": analyzer_reports_qs,
            },
        )
        return Response(serializer.data)

class SubmissionChallengeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, submission_id: int):
        try:
            obj = Case.objects.get(pk=submission_id)
        except Case.DoesNotExist:
            raise NotFound("Submission not found.")

        if obj.reporter_id != request.user.id:
            raise PermissionDenied("Not authorized.")

        if obj.is_challenged:
            return Response({"detail": "Submission already challenged."}, status=400)

        if not obj.is_challengeable:
            return Response({"detail": "Submission cannot be challenged."}, status=400)

        obj.is_challenged = True
        obj.status = "Challenged"
        obj.save(update_fields=["is_challenged", "status", "last_update"])

        return Response({"detail": "Challenge submitted."})

class SubmissionListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SubmissionListSerializer
    pagination_class = SubmissionPagination

    def get_queryset(self):
        qs = Case.objects.select_related(
            "fileOrMail",
            "nonFileIocs",
        )

        mine = self.request.query_params.get("mine")
        if mine in {"1", "true", "True"}:
            qs = qs.filter(reporter=self.request.user)

        ordering = self.request.query_params.get("ordering", "-created_at")
        ordering_map = {
            "created_at": "creation_date",
            "-created_at": "-creation_date",
            "id": "id",
            "-id": "-id",
            "status": "status",
            "-status": "-status",
            "result": "results",
            "-result": "-results",
        }

        db_ordering = ordering_map.get(ordering)
        if db_ordering is None:
            raise ValidationError({"ordering": "Unsupported ordering field."})

        return qs.order_by(db_ordering, "-id")
