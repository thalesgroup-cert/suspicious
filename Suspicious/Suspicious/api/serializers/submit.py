# api/serializers/submit.py
import ipaddress
from urllib.parse import urlparse

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


def _check_no_ssrf_ip(url: str) -> None:
    """
    Reject URLs whose hostname is a private/reserved IP address literal.

    Raises ValueError for blocked addresses. Domain names are not resolved
    here — DNS-time checks are phase-2 work.

    Blocked: loopback, RFC-1918 private, link-local (169.254.x.x / fe80::),
             unique-local IPv6 (fc00::/7), multicast, reserved, unspecified.
    """
    hostname = urlparse(url).hostname  # strips [] from IPv6 literals; None-safe
    if not hostname:
        return

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # hostname is a domain name — pass through

    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        raise ValueError("URL targets a private or reserved address.")


class SubmitUrlSerializer(OptionalContextMixin, serializers.Serializer):
    url = serializers.URLField(required=True)

    def validate_url(self, value: str) -> str:
        value = value.strip()
        # Normalise bare domains that arrive without a scheme.
        # The frontend already prepends http:// for bare domains, but this
        # acts as a safety net in case the value slips through uncorrected.
        if value and not value.startswith(("http://", "https://")):
            value = f"http://{value}"
        try:
            _check_no_ssrf_ip(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value


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