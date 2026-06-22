import ipaddress
import socket
import zipfile as _zipfile
from urllib.parse import urlparse

from django.conf import settings
from rest_framework import serializers


DEFAULT_CONTEXT_MAX_LENGTH = 2000
DEFAULT_OTHER_MAX_LENGTH = 4096
DEFAULT_UPLOAD_MAX_BYTES = 25 * 1024 * 1024  # 25 MB

_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),   # RFC 6598 CGNAT
)


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


def _is_blocked_addr(addr: ipaddress._BaseAddress) -> bool:
    """True if an IP address is private, reserved, or otherwise off-limits.

    Unwraps IPv4-mapped IPv6 (``::ffff:127.0.0.1``) so the mapped IPv4 is
    evaluated, not the harmless-looking IPv6 wrapper.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or any(addr in net for net in _BLOCKED_NETWORKS)
    )


def _looks_like_numeric_host(host: str) -> bool:
    """True for ambiguous numeric host encodings that HTTP clients resolve to
    IPv4 but ``ipaddress.ip_address`` rejects as literals — e.g. decimal
    ``2130706433``, hex ``0x7f000001``, or octal ``0177.0.0.1`` (all 127.0.0.1).

    No legitimate DNS hostname is purely numeric/hex, so treating these as
    suspicious is safe.
    """
    h = host.strip(".")
    if not h:
        return False
    if h.isdigit():                       # packed decimal (e.g. 2130706433)
        return True
    if h.lower().startswith("0x"):        # packed hex (e.g. 0x7f000001)
        return True
    parts = h.split(".")
    if len(parts) <= 4:
        for p in parts:
            if not p:
                return True
            if p.lower().startswith("0x"):               # hex octet
                return True
            if p.startswith("0") and p != "0" and p.isdigit():  # octal octet
                return True
    return False


def _check_no_ssrf_ip(url: str) -> None:
    """
    Reject URLs that point at private/reserved addresses, including via DNS.

    Defences:
      1. IP literals (v4/v6, incl. IPv4-mapped) checked against the block list.
      2. Ambiguous numeric host encodings (decimal/hex/octal) rejected.
      3. Domain names are resolved and **every** returned address is checked,
         so a hostname that resolves to a private/metadata IP is blocked.

    Blocked addresses: loopback, RFC-1918 private, link-local
    (169.254.x.x / fe80::, covers cloud metadata 169.254.169.254),
    unique-local IPv6 (fc00::/7), multicast, reserved, unspecified,
    CGNAT (100.64.0.0/10, RFC 6598).

    Raises ValueError when a blocked target is detected.
    """
    hostname = urlparse(url).hostname  # strips [] from IPv6 literals; None-safe
    if not hostname:
        return

    # 1. Literal IP address?
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        addr = None
    if addr is not None:
        if _is_blocked_addr(addr):
            raise ValueError("URL targets a private or reserved address.")
        return

    # 2. Ambiguous numeric encodings that aren't valid literals but resolve to IPv4.
    if _looks_like_numeric_host(hostname):
        raise ValueError("URL host is an ambiguous numeric address.")

    # 3. Resolve the domain and check every address it maps to (DNS rebinding).
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return  # unresolvable now — any later fetch fails closed anyway
    for info in infos:
        ip = info[4][0]
        try:
            resolved = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if _is_blocked_addr(resolved):
            raise ValueError("URL resolves to a private or reserved address.")


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


_ZIP_MAX_ENTRIES       = 1_000
_ZIP_MAX_UNCOMPRESSED  = 100 * 1024 * 1024   # 100 MB
_ZIP_MAX_RATIO         = 100                 # uncompressed / compressed


def _check_zip_bomb(uploaded_file) -> None:
    name = (getattr(uploaded_file, "name", "") or "").lower()
    if not name.endswith(".zip"):
        return
    try:
        uploaded_file.seek(0)
        with _zipfile.ZipFile(uploaded_file) as zf:
            entries = zf.infolist()
            if len(entries) > _ZIP_MAX_ENTRIES:
                raise serializers.ValidationError(
                    f"Archive contains too many entries ({len(entries)} > {_ZIP_MAX_ENTRIES})."
                )
            total_uncompressed = sum(e.file_size for e in entries)
            if total_uncompressed > _ZIP_MAX_UNCOMPRESSED:
                raise serializers.ValidationError(
                    f"Archive uncompressed size exceeds {_ZIP_MAX_UNCOMPRESSED} bytes."
                )
            compressed = uploaded_file.size or 1
            if compressed > 0 and total_uncompressed / compressed > _ZIP_MAX_RATIO:
                raise serializers.ValidationError(
                    "Archive compression ratio is suspiciously high."
                )
    except _zipfile.BadZipFile:
        raise serializers.ValidationError("File is not a valid ZIP archive.")
    finally:
        uploaded_file.seek(0)


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

        _check_zip_bomb(uploaded_file)

        return uploaded_file


class SubmitConfigSerializer(serializers.Serializer):
    suspicious_email = serializers.EmailField()