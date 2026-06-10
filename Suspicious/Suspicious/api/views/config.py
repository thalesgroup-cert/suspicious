"""GET /api/config/{scope}/ — the config authority endpoint.

Returns a scope's effective config (shared + the scope) with non-secret fields
from the DB runtime tier and secret leaves overlaid from Vault. Sensitive:
the body carries secrets, so it is TLS-only (served via Traefik), authenticated,
and excluded from request logging.
"""
from __future__ import annotations

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
            return Response({"detail": "scope not permitted"}, status=403)
        return Response(get_scope_config(scope))
