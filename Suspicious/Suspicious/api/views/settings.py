# api/views/settings.py
from __future__ import annotations

from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from api.permissions.settings import IsAdminOrCERT
from api.serializers.settings import (
    AnalyzerSettingsSerializer,
    AnalyzerWeightUpdateSerializer,
    CISOUserSerializer,
    EmailFeederStateSerializer,
    EmailFeederStateUpdateSerializer,
    SettingsListBulkCreateSerializer,
)
from api.utils.settings_service import SettingsListSectionService
from cortex_job.models import Analyzer
from profiles.models import CISOProfile
from settings.models import EmailFeederState


READ_ONLY_SECTIONS = {
    "watcher_legit_domains",
    "watcher_monitored_domains",
    "ciso_users",
}


class SettingsPagination(PageNumberPagination):
    """Bounds allow/deny/analyzer list responses. Allow/deny domain lists can
    grow large; an unbounded scan + response is both a perf and a DoS risk."""

    page_size = 100
    page_size_query_param = "page_size"
    max_page_size = 1000


class SettingsListView(generics.GenericAPIView):
    """
    GET  /api/settings/list/<section>/   (paginated: {count, next, previous, results})
    POST /api/settings/list/<section>/
    """

    permission_classes = [IsAdminOrCERT]
    serializer_class = SettingsListBulkCreateSerializer
    pagination_class = SettingsPagination

    def get(self, request, section: str, *args, **kwargs):
        paginator = self.pagination_class()

        if section == "ciso_users":
            queryset = CISOProfile.objects.select_related("user").order_by("user__username")
            page = paginator.paginate_queryset(queryset, request, view=self)
            serializer = CISOUserSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        data = SettingsListSectionService.list_items(section)
        page = paginator.paginate_queryset(data, request, view=self)
        return paginator.get_paginated_response(page)

    def post(self, request, section: str, *args, **kwargs):
        if section in READ_ONLY_SECTIONS:
            raise ValidationError({"detail": f"Section '{section}' is read-only."})

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = SettingsListSectionService.create_items(
            section=section,
            values=serializer.validated_data["values"],
            user=request.user,
        )

        # result = {
        #   "created": [id, ...],
        #   "duplicates": ["val", ...],
        #   "watcher_conflicts": ["val", ...],
        # }
        return Response(result, status=status.HTTP_201_CREATED)


class SettingsListItemDeleteView(generics.GenericAPIView):
    """
    DELETE /api/settings/list/<section>/<item_id>/
    """

    permission_classes = [IsAdminOrCERT]

    def delete(self, request, section: str, item_id: str, *args, **kwargs):
        if section in READ_ONLY_SECTIONS:
            raise ValidationError({"detail": f"Section '{section}' is read-only."})

        deleted_id = SettingsListSectionService.delete_item(section, item_id)
        return Response({"deleted": deleted_id})


class EmailFeederSettingsView(generics.RetrieveUpdateAPIView):
    """
    GET   /api/settings/email-feeder/
    PATCH /api/settings/email-feeder/
    """

    permission_classes = [IsAdminOrCERT]

    def get_object(self) -> EmailFeederState:
        obj, _ = EmailFeederState.objects.get_or_create(id=1)
        return obj

    def get_serializer_class(self):
        if self.request.method in ("PATCH", "PUT"):
            return EmailFeederStateUpdateSerializer
        return EmailFeederStateSerializer

    def retrieve(self, request, *args, **kwargs):
        obj = self.get_object()
        serializer = EmailFeederStateSerializer(obj)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        obj = self.get_object()
        serializer = EmailFeederStateUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        obj.is_running = serializer.validated_data["enabled"]
        obj.save(update_fields=["is_running", "updated_at"])

        return Response(EmailFeederStateSerializer(obj).data)


class AnalyzerSettingsListView(generics.ListAPIView):
    """
    GET /api/settings/analyzers/
    """

    permission_classes = [IsAdminOrCERT]
    serializer_class = AnalyzerSettingsSerializer
    queryset = Analyzer.objects.all().order_by("name")
    pagination_class = SettingsPagination


class AnalyzerSettingsDetailView(generics.UpdateAPIView):
    """
    PATCH /api/settings/analyzers/<analyzer_id>/
    """

    permission_classes = [IsAdminOrCERT]
    serializer_class = AnalyzerWeightUpdateSerializer
    queryset = Analyzer.objects.all()
    lookup_url_kwarg = "analyzer_id"

    def patch(self, request, *args, **kwargs):
        analyzer = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        analyzer.weight = serializer.validated_data["weight"]
        analyzer.save(update_fields=["weight", "last_update"])

        return Response(AnalyzerSettingsSerializer(analyzer).data)