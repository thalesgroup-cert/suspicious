from __future__ import annotations

from django.db import transaction
from django.db.models import Q
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from api.permissions.settings import IsAdminOrCERT
from api.serializers.settings import (
    AnalyzerSettingsSerializer,
    AnalyzerUpdateSerializer,
    CISOUserSerializer,
    EmailFeederStateSerializer,
    EmailFeederStateUpdateSerializer,
    ListChangeLogSerializer,
    SettingsListBulkCreateSerializer,
)
from api.utils.settings_service import SettingsListSectionService
from cortex_job.models import Analyzer, AnalyzerReport
from profiles.models import CISOProfile
from settings.models import EmailFeederState


READ_ONLY_SECTIONS = {
    "watcher_legit_domains",
    "watcher_monitored_domains",
    "ciso_users",
}


def _evidence_kinds_left_unweighted(analyzer: Analyzer, new_weight: float, active_weight: dict) -> list[str]:
    """Kinds of evidence this analyzer covers where the weight sum goes from above 0 to 0.

    A kind is known from the report types the analyzer has produced.
    ponytail: an analyzer that never ran counts as covering nothing, so only the global
    guard protects a kind whose other analyzers have no reports yet.
    """
    kinds = list(
        AnalyzerReport.objects.filter(analyzer=analyzer).values_list("type", flat=True).distinct()
    )
    if not kinds:
        return []
    others = {k: 0.0 for k in kinds}
    for kind, analyzer_id in (
        AnalyzerReport.objects.filter(type__in=kinds).values_list("type", "analyzer_id").distinct()
    ):
        others[kind] += active_weight.get(analyzer_id, 0.0)
    return sorted(
        k for k, rest in others.items()
        if rest + float(analyzer.weight) > 0 and rest + new_weight <= 0
    )


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

        return Response(result, status=status.HTTP_201_CREATED)


class SettingsListItemDeleteView(generics.GenericAPIView):
    """
    DELETE /api/settings/list/<section>/<item_id>/
    """

    permission_classes = [IsAdminOrCERT]

    def delete(self, request, section: str, item_id: str, *args, **kwargs):
        if section in READ_ONLY_SECTIONS:
            raise ValidationError({"detail": f"Section '{section}' is read-only."})

        deleted_id = SettingsListSectionService.delete_item(section, item_id, request.user)
        return Response({"deleted": deleted_id})


class SettingsListHistoryView(generics.ListAPIView):
    """
    GET /api/settings/list/<section>/history/   (paginated, newest first)

    Who added / removed entries. 400 for unknown or read-only sections.
    """

    permission_classes = [IsAdminOrCERT]
    serializer_class = ListChangeLogSerializer
    pagination_class = SettingsPagination

    def get_queryset(self):
        return SettingsListSectionService.history(self.kwargs["section"])


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
    serializer_class = AnalyzerUpdateSerializer
    queryset = Analyzer.objects.all()
    lookup_url_kwarg = "analyzer_id"

    def patch(self, request, *args, **kwargs):
        analyzer = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Scoring divides per kind of evidence (url, ip, domain, hash, file, ...), so the
        # weight must stay above 0 in total and for every kind this analyzer covers:
        # zeroing the last weighted analyzer of one kind would make that evidence score as
        # Safe. Inactive analyzers are never scheduled and so cannot hold a sum up. The
        # active rows are locked in pk order (one query, own row included, so two
        # concurrent updates serialise instead of deadlocking) and the check and the save
        # share one transaction, so two requests cannot each see the other's old weight.
        with transaction.atomic():
            if "weight" in serializer.validated_data and analyzer.is_active:
                new_weight = float(serializer.validated_data["weight"])
                locked = list(
                    Analyzer.objects.select_for_update()
                    .filter(Q(is_active=True) | Q(pk=analyzer.pk))
                    .order_by("pk")
                    .values_list("pk", "weight", "is_active")
                )
                active_weight = {pk: w for pk, w, active in locked if active and pk != analyzer.pk}
                if sum(active_weight.values()) + new_weight <= 0:
                    raise ValidationError(
                        {"weight": ["At least one active analyzer must keep a weight above 0."]}
                    )
                emptied = _evidence_kinds_left_unweighted(analyzer, new_weight, active_weight)
                if emptied:
                    raise ValidationError({"weight": [
                        "No other active analyzer would keep a weight above 0 for "
                        + ", ".join(emptied) + " evidence, which would then always score Safe."
                    ]})

            update_fields = ["last_update"]
            for field in ("weight", "tier"):
                if field in serializer.validated_data:
                    setattr(analyzer, field, serializer.validated_data[field])
                    update_fields.append(field)
            analyzer.save(update_fields=update_fields)

        return Response(AnalyzerSettingsSerializer(analyzer).data)