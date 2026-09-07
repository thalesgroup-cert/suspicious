import logging

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers.submit import (
    SubmitConfigSerializer,
    SubmitFileSerializer,
    SubmitIndicatorsSerializer,
    SubmitOtherSerializer,
    SubmitUrlSerializer,
    _check_no_ssrf_ip,
)
from api.utils.indicators import expand_wrappers, parse_indicators
from case_handler.case_utils.case_handler import CaseHandler
from cortex_job.cortex_utils.case_targets import collect_case_targets
from tasp.forms import UploadFileForm, UploadOtherForm, UploadURLForm
from tasp.tasks import dispatch_case_analysis

IOC_GROUP_MAX = 100

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
        "id": case_id,
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
        allow_reason=results.get("allow_reason", ""),
    )
    if case is not None:
        handler.dispatch_pending(case)
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


class SubmitIndicatorsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ser = SubmitIndicatorsSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)

        parsed = parse_indicators(ser.validated_data["indicators"])
        # Unwrap SafeLinks / URLDefense links so the real target also becomes an
        # observable — before the cap + SSRF checks below, so the unwrapped
        # targets are subject to both.
        valid = expand_wrappers([p for p in parsed if p.type])
        skipped = [p.raw for p in parsed if not p.type]

        # Cap first — before any per-indicator work (the SSRF check below can
        # do a DNS lookup per URL). The field also has a max_length, this is
        # the semantic limit.
        if not valid:
            return _error_response(
                detail="No valid indicator found.",
                http_status=status.HTTP_400_BAD_REQUEST,
            )
        if len(valid) > IOC_GROUP_MAX:
            return _error_response(
                detail=f"Too many indicators ({len(valid)}). The limit is {IOC_GROUP_MAX} per submission.",
                http_status=status.HTTP_400_BAD_REQUEST,
            )

        # SSRF parity with SubmitUrlSerializer: a URL indicator that targets a
        # private / reserved / link-local address (incl. 169.254.169.254) is
        # dropped to `skipped`, not created + dispatched.
        safe_valid = []
        for p in valid:
            if p.type == "url":
                try:
                    _check_no_ssrf_ip(p.value)
                except ValueError:
                    skipped.append(p.raw)
                    continue
            safe_valid.append(p)
        valid = safe_valid

        if not valid:
            return _error_response(
                detail="No valid indicator found (all were unresolvable or blocked).",
                http_status=status.HTTP_400_BAD_REQUEST,
            )

        from django.db import transaction

        from case_handler.case_utils.case_creator import CaseCreator
        from case_handler.models import ObservableGroup, ObservableGroupArtifact
        from domain_process.models import Domain
        from hash_process.models import Hash
        from ip_process.models import IP
        from url_process.models import URL

        _MODEL = {
            "url": (URL, "address", "url"),
            "ip": (IP, "address", "ip"),
            "hash": (Hash, "value", "hash"),
            "domain": (Domain, "value", "domain"),
        }

        def _resolve(model, field, value):
            # These columns have no unique constraint, so a concurrent submit
            # can leave duplicates; take the first rather than raising
            # MultipleObjectsReturned on every later submission of that value.
            existing = model.objects.filter(**{field: value}).first()
            return existing or model.objects.create(**{field: value})

        context = ser.validated_data.get("context") or ""

        class _NoCase(Exception):
            pass

        try:
            with transaction.atomic():
                group = ObservableGroup.objects.create(label=context[:255])
                for p in valid:
                    model, field, art_field = _MODEL[p.type]
                    obj = _resolve(model, field, p.value)
                    ObservableGroupArtifact.objects.create(
                        group=group, artifact_type=p.type.upper(), **{art_field: obj}
                    )

                case = CaseCreator(request.user).create_case(
                    description=context, reporter_context=context,
                    observable_group_instance=group,
                )
                if case is None:
                    raise _NoCase
        except _NoCase:
            # atomic() rolled the group + artifacts back — no orphans.
            logger.error("SubmitIndicatorsView: CaseCreator returned no case")
            return _error_response(
                detail="An internal error occurred while creating the case.",
                code="internal_error",
                http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        targets = collect_case_targets(case)
        intents = [
            (f"{inst._meta.app_label}.{inst._meta.model_name}", inst.pk, data_type)
            for inst, data_type in targets
        ]
        dispatch_case_analysis.delay(case.id, intents)

        return Response(
            {
                "status": "success",
                "case_id": case.id,
                "observable_count": len(valid),
                "accepted": True,
                "skipped": skipped,
            },
            status=status.HTTP_201_CREATED,
        )


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