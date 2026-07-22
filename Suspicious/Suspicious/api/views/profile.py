import logging

from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from profiles.models import UserProfile, CISOProfile
from profiles.profiles_utils.avatar_storage import (
    AVATAR_MAX_BYTES,
    InvalidAvatarImage,
    delete_avatar,
    process_avatar_image,
    store_avatar,
)
from api.serializers.profile import (
    UserProfileSerializer,
    CISOProfileSerializer,
    AppearanceSerializer,
    PreferencesSerializer,
    SemanticColorsSerializer,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
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
# ---------------------------------------------------------------------------

class AppearanceView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        profile, ProfileSerializerClass = _get_profile(request.user)
        serializer = AppearanceSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.update(profile, serializer.validated_data)

        return Response(ProfileSerializerClass(profile).data)


# ---------------------------------------------------------------------------
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
                "profile": ProfileSerializerClass(profile).data,
            }
        )


# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# POST /api/profile/avatar/upload/
# ---------------------------------------------------------------------------

class AvatarUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request):
        upload = request.FILES.get("avatar")
        if upload is None:
            return Response({"detail": "No file provided."}, status=400)

        if upload.size > AVATAR_MAX_BYTES:
            return Response(
                {
                    "detail": f"File too large: {upload.size} bytes (max {AVATAR_MAX_BYTES})"
                },
                status=400,
            )

        try:
            processed = process_avatar_image(
                content_type=upload.content_type,
                size=upload.size,
                raw=upload.read(),
            )
        except InvalidAvatarImage:
            logger.exception(
                "avatar process_avatar_image failed validation for user_id=%s",
                request.user.id,
            )
            return Response({"detail": "Invalid avatar image."}, status=400)

        profile, SerializerClass = _get_profile(request.user)
        old_avatar = profile.avatar or {}

        try:
            key = store_avatar(request.user.id, processed)
        except Exception:
            logger.exception(
                "avatar store_avatar failed for user_id=%s", request.user.id
            )
            return Response(
                {"detail": "Avatar storage is unavailable."}, status=502
            )

        if old_avatar.get("style") == "upload" and old_avatar.get("seed"):
            delete_avatar(old_avatar["seed"])

        profile.avatar = {"style": "upload", "seed": key}
        profile.save(update_fields=["avatar", "last_update"])

        return Response(SerializerClass(profile).data)