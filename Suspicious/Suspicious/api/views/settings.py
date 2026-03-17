# api/views/settings.py
from __future__ import annotations

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
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


class SettingsListView(generics.GenericAPIView):
    """
    GET  /api/settings/list/<section>/
    POST /api/settings/list/<section>/
    """

    permission_classes = [IsAdminOrCERT]
    serializer_class = SettingsListBulkCreateSerializer

    def get(self, request, section: str, *args, **kwargs):
        if section == "ciso_users":
            queryset = CISOProfile.objects.select_related("user").order_by("user__username")
            serializer = CISOUserSerializer(queryset, many=True)
            return Response(serializer.data)

        data = SettingsListSectionService.list_items(section)
        return Response(data)

    def post(self, request, section: str, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        created_ids = SettingsListSectionService.create_items(
            section=section,
            values=serializer.validated_data["values"],
            user=request.user,
        )
        return Response({"created": created_ids}, status=status.HTTP_201_CREATED)


class SettingsListItemDeleteView(generics.GenericAPIView):
    """
    DELETE /api/settings/list/<section>/<item_id>/
    """

    permission_classes = [IsAdminOrCERT]

    def delete(self, request, section: str, item_id: str, *args, **kwargs):
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