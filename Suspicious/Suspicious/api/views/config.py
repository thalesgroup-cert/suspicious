"""GET /api/config/{scope}/ — the config authority endpoint.

Returns a scope's effective config (shared + the scope) with non-secret fields
from the DB runtime tier and secret leaves overlaid from Vault. Sensitive: the
body carries secrets. Access is restricted to the isolated internal Docker
network (or TLS when reached via Traefik), requires a scoped token, sets
Cache-Control: no-store, and is excluded from request logging.
"""
from __future__ import annotations

from django.utils.cache import add_never_cache_headers
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from settings.config import SCOPE_SECTIONS, get_scope_config


def _allowed_scopes(user) -> set[str]:
    if user.is_superuser:
        return set(SCOPE_SECTIONS.keys())
    return set(user.groups.values_list("name", flat=True)) & set(SCOPE_SECTIONS.keys())


class ServiceConfigView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "service_config"

    def get(self, request, scope: str):
        if scope == "shared" or scope not in _allowed_scopes(request.user):
            return Response({"detail": "scope not permitted"}, status=status.HTTP_403_FORBIDDEN)
        response = Response(get_scope_config(scope))
        add_never_cache_headers(response)
        return response
