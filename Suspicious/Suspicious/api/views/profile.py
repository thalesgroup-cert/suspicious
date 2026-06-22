from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from profiles.models import UserProfile, CISOProfile
from api.serializers.profile import (
    UserProfileSerializer,
    CISOProfileSerializer,
    AppearanceSerializer,
    PreferencesSerializer,
    SemanticColorsSerializer,
)


# ---------------------------------------------------------------------------
# Helper — resolve the correct profile model for the requesting user.
#
# CISOProfile takes priority: users with a CISO profile get CISO
# serialization (which includes the scope field).
# ---------------------------------------------------------------------------

def _get_profile(user):
    """
    Returns (profile_instance, serializer_class).
    Creates a UserProfile on first access if neither profile exists.
    """
    try:
        return user.cisoprofile, CISOProfileSerializer
    except CISOProfile.DoesNotExist:
        pass

    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile, UserProfileSerializer


# ---------------------------------------------------------------------------
# GET / PATCH /api/profile/
# ---------------------------------------------------------------------------

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, SerializerClass = _get_profile(request.user)
        return Response(SerializerClass(profile).data)

    def patch(self, request):
        profile, SerializerClass = _get_profile(request.user)
        serializer = SerializerClass(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# ---------------------------------------------------------------------------
# PATCH /api/profile/appearance/
# Updates: theme, auto_seasonal, semantic_colors (any combination).
# ---------------------------------------------------------------------------

class AppearanceView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        profile, ProfileSerializerClass = _get_profile(request.user)
        serializer = AppearanceSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.update(profile, serializer.validated_data)

        # Return the full profile so the frontend can update its cache.
        return Response(ProfileSerializerClass(profile).data)


# ---------------------------------------------------------------------------
# PATCH /api/profile/preferences/
# Updates: wants_acknowledgement, wants_results.
# ---------------------------------------------------------------------------

class PreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        profile, ProfileSerializerClass = _get_profile(request.user)
        serializer = PreferencesSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.update(profile, serializer.validated_data)

        return Response(ProfileSerializerClass(profile).data)


# ---------------------------------------------------------------------------
# GET / PATCH /api/profile/colors/
#
# Dedicated endpoint for semantic color sync.
#
# GET  — returns just the semantic_colors blob (merged with defaults).
# PATCH — accepts a full or partial semantic_colors object, validates,
#         persists, and returns the merged result.
#
# The frontend calls this on:
#   1. Preset switch in ColorSettingsPanel
#   2. Individual swatch change (debounced 800ms)
#   3. ProfilePage "Save appearance" button
# ---------------------------------------------------------------------------

class SemanticColorsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = _get_profile(request.user)
        return Response({"semantic_colors": profile.get_semantic_colors()})

    def patch(self, request):
        profile, ProfileSerializerClass = _get_profile(request.user)
        serializer = SemanticColorsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(profile, serializer.validated_data)

        return Response(
            {
                "semantic_colors": profile.get_semantic_colors(),
                # Echo the full profile so a single roundtrip is enough.
                "profile": ProfileSerializerClass(profile).data,
            }
        )


# ---------------------------------------------------------------------------
# POST /api/profile/colors/reset/
# Resets semantic_colors to DEFAULT_SEMANTIC_COLORS.
# ---------------------------------------------------------------------------

class ResetSemanticColorsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from profiles.models import DEFAULT_SEMANTIC_COLORS
        import copy

        profile, ProfileSerializerClass = _get_profile(request.user)
        profile.semantic_colors = copy.deepcopy(DEFAULT_SEMANTIC_COLORS)
        profile.save(update_fields=["semantic_colors", "last_update"])

        return Response(
            {
                "semantic_colors": profile.get_semantic_colors(),
                "profile": ProfileSerializerClass(profile).data,
            }
        )