from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from profiles.models import UserProfile, CISOProfile
from api.serializers.profile import ProfileSerializer, UpdatePreferencesSerializer, UpdateAppearanceSerializer


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get_profile_instance(self, user):
        groups = set(user.groups.values_list("name", flat=True))
        if "CISO" in groups:
            profile, _ = CISOProfile.objects.get_or_create(
                user=user,
                defaults={
                    "function": "",
                    "gbu": "",
                    "country": "",
                    "region": "",
                    "scope": "Not defined",
                },
            )
            return profile

        profile, _ = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                "function": "",
                "gbu": "",
                "country": "",
                "region": "",
            },
        )
        return profile

    def get(self, request):
        profile = self.get_profile_instance(request.user)

        data = {
            "wants_acknowledgement": profile.wants_acknowledgement,
            "wants_results": profile.wants_results,
            "theme": profile.theme,
            "auto_seasonal": profile.auto_seasonal,
        }

        serializer = ProfileSerializer(data)
        return Response(serializer.data)


class ProfilePreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def get_profile_instance(self, user):
        groups = set(user.groups.values_list("name", flat=True))
        if "CISO" in groups:
            profile, _ = CISOProfile.objects.get_or_create(
                user=user,
                defaults={
                    "function": "",
                    "gbu": "",
                    "country": "",
                    "region": "",
                    "scope": "Not defined",
                },
            )
            return profile

        profile, _ = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                "function": "",
                "gbu": "",
                "country": "",
                "region": "",
            },
        )
        return profile

    def patch(self, request):
        serializer = UpdatePreferencesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        profile = self.get_profile_instance(request.user)
        profile.wants_acknowledgement = serializer.validated_data["wants_acknowledgement"]
        profile.wants_results = serializer.validated_data["wants_results"]
        profile.save(update_fields=["wants_acknowledgement", "wants_results", "last_update"])

        return Response({
            "wants_acknowledgement": profile.wants_acknowledgement,
            "wants_results": profile.wants_results,
        })


class ProfileAppearanceView(APIView):
    permission_classes = [IsAuthenticated]

    def get_profile_instance(self, user):
        groups = set(user.groups.values_list("name", flat=True))
        if "CISO" in groups:
            profile, _ = CISOProfile.objects.get_or_create(
                user=user,
                defaults={
                    "function": "",
                    "gbu": "",
                    "country": "",
                    "region": "",
                    "scope": "Not defined",
                },
            )
            return profile

        profile, _ = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                "function": "",
                "gbu": "",
                "country": "",
                "region": "",
            },
        )
        return profile

    def patch(self, request, *args, **kwargs):
        profile = self.get_profile_instance(request.user)  # ou ta logique CISO/UserProfile
        serializer = UpdateAppearanceSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if "theme" in serializer.validated_data:
            profile.theme = serializer.validated_data["theme"]

        if "auto_seasonal" in serializer.validated_data:
            profile.auto_seasonal = serializer.validated_data["auto_seasonal"]

        profile.save(update_fields=["theme", "auto_seasonal", "last_update"])

        return Response(
            {
                "theme": profile.theme,
                "auto_seasonal": profile.auto_seasonal,
                "wants_acknowledgement": profile.wants_acknowledgement,
                "wants_results": profile.wants_results,
            },
            status=status.HTTP_200_OK,
        )