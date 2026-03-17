from django.db import transaction
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers.profile import (
    AppearancePatchSerializer,
    AppearanceResponseSerializer,
    PreferencesPatchSerializer,
    PreferencesResponseSerializer,
    ProfileSerializer,
)
from api.utils.profile_service import ProfileService


class BaseProfileAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get_profile(self):
        return ProfileService.get_or_create_profile(self.request.user)


class ProfileView(BaseProfileAPIView):
    serializer_class = ProfileSerializer

    def get(self, request, *args, **kwargs):
        profile = self.get_profile()
        serializer = self.get_serializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProfilePreferencesView(BaseProfileAPIView):
    serializer_class = PreferencesPatchSerializer
    response_serializer_class = PreferencesResponseSerializer

    @transaction.atomic
    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        profile = self.get_profile()
        changed_fields = ProfileService.apply_updates(profile, serializer.validated_data)

        if changed_fields:
            profile.save(update_fields=[*changed_fields, "last_update"])

        response_data = self.response_serializer_class(profile).data
        return Response(response_data, status=status.HTTP_200_OK)


class ProfileAppearanceView(BaseProfileAPIView):
    serializer_class = AppearancePatchSerializer
    response_serializer_class = AppearanceResponseSerializer

    @transaction.atomic
    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        profile = self.get_profile()
        changed_fields = ProfileService.apply_updates(profile, serializer.validated_data)

        if changed_fields:
            profile.save(update_fields=[*changed_fields, "last_update"])

        response_data = self.response_serializer_class(profile).data
        return Response(response_data, status=status.HTTP_200_OK)