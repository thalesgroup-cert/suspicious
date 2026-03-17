from django.conf import settings
from rest_framework import serializers


DEFAULT_CONTEXT_MAX_LENGTH = 2000
DEFAULT_OTHER_MAX_LENGTH = 4096
DEFAULT_UPLOAD_MAX_BYTES = 25 * 1024 * 1024  # 25 MB


class OptionalContextMixin(serializers.Serializer):
    context = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        max_length=getattr(settings, "SUBMIT_CONTEXT_MAX_LENGTH", DEFAULT_CONTEXT_MAX_LENGTH),
        trim_whitespace=True,
    )

    def normalize_context(self):
        context = self.validated_data.get("context")
        if context is None:
            return ""
        return context.strip()


class SubmitUrlSerializer(OptionalContextMixin, serializers.Serializer):
    url = serializers.URLField(required=True)

    def validate_url(self, value: str) -> str:
        return value.strip()


class SubmitOtherSerializer(OptionalContextMixin, serializers.Serializer):
    value = serializers.CharField(
        required=True,
        max_length=getattr(settings, "SUBMIT_OTHER_MAX_LENGTH", DEFAULT_OTHER_MAX_LENGTH),
        trim_whitespace=True,
    )

    def validate_value(self, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise serializers.ValidationError("This field may not be blank.")
        return normalized


class SubmitFileSerializer(OptionalContextMixin, serializers.Serializer):
    file = serializers.FileField(required=True)

    def validate_file(self, uploaded_file):
        if uploaded_file.size <= 0:
            raise serializers.ValidationError("Uploaded file is empty.")

        max_bytes = getattr(settings, "SUBMIT_FILE_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES)
        if uploaded_file.size > max_bytes:
            raise serializers.ValidationError(
                f"Uploaded file exceeds the maximum allowed size of {max_bytes} bytes."
            )

        filename = getattr(uploaded_file, "name", "") or ""
        if len(filename) > 255:
            raise serializers.ValidationError("Filename is too long.")

        return uploaded_file


class SubmitConfigSerializer(serializers.Serializer):
    suspicious_email = serializers.EmailField()