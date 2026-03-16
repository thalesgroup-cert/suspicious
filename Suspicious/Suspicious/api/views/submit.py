from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

from tasp.forms import UploadFileForm, UploadURLForm, UploadOtherForm
from case_handler.case_utils.case_handler import CaseHandler
from api.serializers.submit import SubmitConfigSerializer, SubmitUrlSerializer, SubmitOtherSerializer, SubmitFileSerializer


def process_case(request, file_form, url_form, other_form):
    handler = CaseHandler(request, file_form, url_form, other_form)
    results = handler.validate_forms()
    case = handler.handle_case(
        file_inst=results["file_instance"],
        mail_inst=results["mail_instance"],
        ip_inst=results["ip_instance"],
        url_inst=results["url_instance"],
        hash_inst=results["hash_instance"],
        allow_listed=results["allow_listed"],
    )
    return case, results


class SubmitConfigView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", "suspicious@example.com")
        serializer = SubmitConfigSerializer({"suspicious_email": suspicious_email})
        return Response(serializer.data)


class SubmitUrlView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SubmitUrlSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file_form = UploadFileForm()
        url_form = UploadURLForm(data={"url": serializer.validated_data["url"]})
        other_form = UploadOtherForm()

        case, _results = process_case(request, file_form, url_form, other_form)

        if not case:
            return Response({"detail": "Submission failed during processing."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"id": case.id, "message": "URL submitted successfully."},
            status=status.HTTP_201_CREATED,
        )


class SubmitOtherView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SubmitOtherSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file_form = UploadFileForm()
        url_form = UploadURLForm()
        other_form = UploadOtherForm(data={"other": serializer.validated_data["value"]})

        case, _results = process_case(request, file_form, url_form, other_form)

        if not case:
            return Response({"detail": "Submission failed during processing."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"id": case.id, "message": "Indicator submitted successfully."},
            status=status.HTTP_201_CREATED,
        )


class SubmitFileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SubmitFileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]

        file_form = UploadFileForm(data={}, files={"file": uploaded_file})
        url_form = UploadURLForm()
        other_form = UploadOtherForm()

        case, results = process_case(request, file_form, url_form, other_form)

        if case:
            return Response(
                {"id": case.id, "message": "File submitted successfully."},
                status=status.HTTP_201_CREATED,
            )

        if results.get("mail_instance"):
            return Response(
                {"message": "Mail submitted successfully."},
                status=status.HTTP_201_CREATED,
            )

        return Response({"detail": "Submission failed during processing."}, status=status.HTTP_400_BAD_REQUEST)