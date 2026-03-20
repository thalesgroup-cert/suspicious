# api/views/submit.py
import logging

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers.submit import (
    SubmitConfigSerializer,
    SubmitFileSerializer,
    SubmitOtherSerializer,
    SubmitUrlSerializer,
)
from case_handler.case_utils.case_handler import CaseHandler
from tasp.forms import UploadFileForm, UploadOtherForm, UploadURLForm

logger = logging.getLogger(__name__)


def _build_submission_response(
    *,
    message: str,
    submission_type: str,
    case=None,
    accepted: bool = True,
    result_type: str = "case",
    http_status: int = status.HTTP_201_CREATED,
):
    case_id = getattr(case, "id", None)
    payload = {
        "status": "success",
        "accepted": accepted,
        "submission_type": submission_type,
        "result_type": result_type,
        "case_id": case_id,
        "id": case_id,  # compatibility with current frontend
        "message": message,
    }
    return Response(payload, status=http_status)


def _error_response(
    *,
    detail: str,
    code: str = "submission_failed",
    http_status: int = status.HTTP_400_BAD_REQUEST,
    extra: dict | None = None,
):
    payload = {
        "status": "error",
        "code": code,
        "detail": detail,
    }
    if extra:
        payload.update(extra)
    return Response(payload, status=http_status)


def process_case(request, file_form, url_form, other_form):
    handler = CaseHandler(request, file_form, url_form, other_form)
    results = handler.validate_forms()
    case = handler.handle_case(
        file_inst=results.get("file_instance"),
        mail_inst=results.get("mail_instance"),
        ip_inst=results.get("ip_instance"),
        url_inst=results.get("url_instance"),
        hash_inst=results.get("hash_instance"),
        allow_listed=results.get("allow_listed"),
    )
    return case, results


class BaseSubmitView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = None
    submission_type = None
    success_message = "Submission accepted."

    def get_serializer(self, *args, **kwargs):
        assert self.serializer_class is not None, "serializer_class must be set"
        return self.serializer_class(*args, **kwargs)

    def build_forms(self, validated_data):
        raise NotImplementedError

    def handle_success(self, case, results):
        if case:
            return _build_submission_response(
                message=self.success_message,
                submission_type=self.submission_type,
                case=case,
                result_type="case",
            )

        # Submission was accepted but matched the allow-list — no case is
        # expected. Return 200 so the frontend doesn't treat it as an error.
        if results.get("allow_listed"):
            return _build_submission_response(
                message="Submission accepted (allowlisted — no case created).",
                submission_type=self.submission_type,
                case=None,
                accepted=True,
                result_type="case",
                http_status=status.HTTP_200_OK,
            )

        return _error_response(
            detail="Submission failed during processing.",
            code="processing_failed",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            file_form, url_form, other_form = self.build_forms(serializer.validated_data)
            case, results = process_case(request, file_form, url_form, other_form)
            return self.handle_success(case, results)
        except serializers.ValidationError:
            raise
        except Exception:
            logger.exception(
                "Unhandled error while processing %s submission for user_id=%s",
                self.submission_type,
                getattr(request.user, "id", None),
            )
            return _error_response(
                detail="An internal error occurred while processing the submission.",
                code="internal_error",
                http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SubmitConfigView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", "suspicious@example.com")
        serializer = SubmitConfigSerializer({"suspicious_email": suspicious_email})
        return Response(
            {
                "status": "success",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class SubmitUrlView(BaseSubmitView):
    serializer_class = SubmitUrlSerializer
    submission_type = "url"
    success_message = "URL submitted successfully."

    def build_forms(self, validated_data):
        context = validated_data.get("context") or ""

        file_form = UploadFileForm()
        url_form = UploadURLForm(
            data={
                "url": validated_data["url"],
                "context": context,
            }
        )
        other_form = UploadOtherForm()
        return file_form, url_form, other_form


class SubmitOtherView(BaseSubmitView):
    serializer_class = SubmitOtherSerializer
    submission_type = "other"
    success_message = "Indicator submitted successfully."

    def build_forms(self, validated_data):
        context = validated_data.get("context") or ""

        file_form = UploadFileForm()
        url_form = UploadURLForm()
        other_form = UploadOtherForm(
            data={
                "other": validated_data["value"],
                "context": context,
            }
        )
        return file_form, url_form, other_form


class SubmitFileView(BaseSubmitView):
    serializer_class = SubmitFileSerializer
    submission_type = "file"
    success_message = "File submitted successfully."

    def build_forms(self, validated_data):
        uploaded_file = validated_data["file"]
        context = validated_data.get("context") or ""

        file_form = UploadFileForm(
            data={"context": context},
            files={"file": uploaded_file},
        )
        url_form = UploadURLForm()
        other_form = UploadOtherForm()
        return file_form, url_form, other_form

    def handle_success(self, case, results):
        if case:
            return _build_submission_response(
                message="File submitted successfully.",
                submission_type=self.submission_type,
                case=case,
                result_type="case",
            )

        if results.get("mail_instance"):
            return _build_submission_response(
                message="Mail submitted successfully.",
                submission_type=self.submission_type,
                case=None,
                result_type="mail",
            )

        # Allow-listed files: accepted but no case or mail produced.
        if results.get("allow_listed"):
            return _build_submission_response(
                message="Submission accepted (allowlisted — no case created).",
                submission_type=self.submission_type,
                case=None,
                accepted=True,
                result_type="case",
                http_status=status.HTTP_200_OK,
            )

        return _error_response(
            detail="Submission failed during processing.",
            code="processing_failed",
            http_status=status.HTTP_400_BAD_REQUEST,
        )