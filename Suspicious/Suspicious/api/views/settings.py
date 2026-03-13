from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from profiles.models import CISOProfile
from settings.models import (
    AllowListDomain,
    DenyListDomain,
    CampaignDomainAllowList,
    AllowListFile,
    AllowListFiletype,
    EmailFeederState,
)
from domain_process.models import Domain
from hash_process.models import Hash
from cortex_job.models import Analyzer
from api.serializers.settings import (
    CISOUserSerializer,
    EmailFeederStateSerializer,
    AnalyzerSettingsSerializer,
)

from rest_framework.exceptions import PermissionDenied, ValidationError

def user_is_admin_or_cert(user):
    return user.groups.filter(name__in=["Admin", "CERT"]).exists()

class SettingsPermissionMixin:
    permission_classes = [IsAuthenticated]

    def check_settings_permission(self, request):
        if not user_is_admin_or_cert(request.user):
            raise PermissionDenied("Admin/CERT only.")



class SettingsListView(SettingsPermissionMixin, APIView):
    """
    GET  /api/settings/list/<section>/
    POST /api/settings/list/<section>/
    """

    def get(self, request, section):
        self.check_settings_permission(request)

        if section == "domains_allow":
            data = [
                {
                    "id": str(obj.id),
                    "value": obj.domain.value if obj.domain else "",
                    "created_at": obj.creation_date,
                }
                for obj in AllowListDomain.objects.select_related("domain").order_by("-creation_date")
            ]
            return Response(data)

        if section == "domains_deny":
            data = [
                {
                    "id": str(obj.id),
                    "value": obj.domain.value if obj.domain else "",
                    "created_at": obj.creation_date,
                }
                for obj in DenyListDomain.objects.select_related("domain").order_by("-creation_date")
            ]
            return Response(data)

        if section == "campaign_domains_allow":
            data = [
                {
                    "id": str(obj.id),
                    "value": obj.domain.value if obj.domain else "",
                    "created_at": obj.creation_date,
                }
                for obj in CampaignDomainAllowList.objects.select_related("domain").order_by("-creation_date")
            ]
            return Response(data)

        if section == "emails_files_allow":
            data = [
                {
                    "id": str(obj.id),
                    "value": obj.linked_file_hash.value if obj.linked_file_hash else "",
                    "created_at": obj.creation_date,
                }
                for obj in AllowListFile.objects.select_related("linked_file_hash").order_by("-creation_date")
            ]
            return Response(data)

        if section == "filetypes_allow":
            data = [
                {
                    "id": str(obj.id),
                    "value": obj.filetype,
                    "created_at": obj.creation_date,
                }
                for obj in AllowListFiletype.objects.order_by("-creation_date")
            ]
            return Response(data)

        if section == "ciso_users":
            qs = CISOProfile.objects.select_related("user").order_by("user__username")
            return Response(CISOUserSerializer(qs, many=True).data)

        raise ValidationError({"section": "Invalid section."})

    def post(self, request, section):
        self.check_settings_permission(request)

        values = request.data.get("values", [])
        if not isinstance(values, list):
            raise ValidationError({"values": "Must be a list."})

        cleaned = []
        for v in values:
            s = str(v).strip()
            if s:
                cleaned.append(s)

        if not cleaned:
            raise ValidationError({"values": "No valid values provided."})

        created_ids = []

        with transaction.atomic():
            if section == "domains_allow":
                for value in cleaned:
                    domain, _ = Domain.objects.get_or_create(value=value)
                    obj, _ = AllowListDomain.objects.get_or_create(
                        domain=domain,
                        user=request.user,
                    )
                    created_ids.append(obj.id)
                return Response({"created": created_ids}, status=status.HTTP_201_CREATED)

            if section == "domains_deny":
                for value in cleaned:
                    domain, _ = Domain.objects.get_or_create(value=value)
                    obj, _ = DenyListDomain.objects.get_or_create(
                        domain=domain,
                        user=request.user,
                    )
                    created_ids.append(obj.id)
                return Response({"created": created_ids}, status=status.HTTP_201_CREATED)

            if section == "campaign_domains_allow":
                for value in cleaned:
                    domain, _ = Domain.objects.get_or_create(value=value)
                    obj, _ = CampaignDomainAllowList.objects.get_or_create(
                        domain=domain,
                        user=request.user,
                    )
                    created_ids.append(obj.id)
                return Response({"created": created_ids}, status=status.HTTP_201_CREATED)

            if section == "emails_files_allow":
                for value in cleaned:
                    file_hash, _ = Hash.objects.get_or_create(value=value)
                    obj, _ = AllowListFile.objects.get_or_create(
                        linked_file_hash=file_hash,
                        user=request.user,
                    )
                    created_ids.append(obj.id)
                return Response({"created": created_ids}, status=status.HTTP_201_CREATED)

            if section == "filetypes_allow":
                for value in cleaned:
                    obj, _ = AllowListFiletype.objects.get_or_create(
                        filetype=value,
                        user=request.user,
                    )
                    created_ids.append(obj.id)
                return Response({"created": created_ids}, status=status.HTTP_201_CREATED)

        raise ValidationError({"section": "Invalid section."})

class SettingsListItemDeleteView(SettingsPermissionMixin, APIView):
    """
    DELETE /api/settings/list/<section>/<item_id>/
    """

    def delete(self, request, section, item_id):
        self.check_settings_permission(request)

        if section == "domains_allow":
            deleted, _ = AllowListDomain.objects.filter(id=item_id).delete()
        elif section == "domains_deny":
            deleted, _ = DenyListDomain.objects.filter(id=item_id).delete()
        elif section == "campaign_domains_allow":
            deleted, _ = CampaignDomainAllowList.objects.filter(id=item_id).delete()
        elif section == "emails_files_allow":
            deleted, _ = AllowListFile.objects.filter(id=item_id).delete()
        elif section == "filetypes_allow":
            deleted, _ = AllowListFiletype.objects.filter(id=item_id).delete()
        elif section == "ciso_users":
            deleted, _ = CISOProfile.objects.filter(id=item_id).delete()
        else:
            raise ValidationError({"section": "Invalid section."})

        if deleted == 0:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({"deleted": str(item_id)})

class EmailFeederSettingsView(SettingsPermissionMixin, APIView):
    """
    GET   /api/settings/email-feeder/
    PATCH /api/settings/email-feeder/
    """

    def get_object(self):
        obj, _ = EmailFeederState.objects.get_or_create(id=1)
        return obj

    def get(self, request):
        self.check_settings_permission(request)
        obj = self.get_object()
        return Response(EmailFeederStateSerializer(obj).data)

    def patch(self, request):
        self.check_settings_permission(request)
        obj = self.get_object()

        enabled = request.data.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationError({"enabled": "Must be a boolean."})

        obj.is_running = enabled
        obj.save(update_fields=["is_running", "updated_at"])

        return Response(EmailFeederStateSerializer(obj).data)

class AnalyzerSettingsListView(SettingsPermissionMixin, APIView):
    """
    GET /api/settings/analyzers/
    """

    def get(self, request):
        self.check_settings_permission(request)
        qs = Analyzer.objects.all().order_by("name")
        return Response(AnalyzerSettingsSerializer(qs, many=True).data)


class AnalyzerSettingsDetailView(SettingsPermissionMixin, APIView):
    """
    PATCH /api/settings/analyzers/<analyzer_id>/
    """

    def patch(self, request, analyzer_id):
        self.check_settings_permission(request)

        try:
            analyzer = Analyzer.objects.get(id=analyzer_id)
        except Analyzer.DoesNotExist:
            return Response({"detail": "Analyzer not found."}, status=status.HTTP_404_NOT_FOUND)

        weight = request.data.get("weight")
        try:
            weight = float(weight)
        except (TypeError, ValueError):
            raise ValidationError({"weight": "Must be a number."})

        analyzer.weight = weight
        analyzer.save(update_fields=["weight", "last_update"])

        return Response(AnalyzerSettingsSerializer(analyzer).data)
