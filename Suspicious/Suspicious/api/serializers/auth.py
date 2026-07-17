from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from profiles.models import CISOProfile, UserProfile, merge_semantic_colors

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_profile_for_user(user):
    """
    Returns the profile instance (CISOProfile takes priority).
    Returns None if neither profile exists.
    """
    try:
        return user.cisoprofile
    except CISOProfile.DoesNotExist:
        pass
    try:
        return user.userprofile
    except UserProfile.DoesNotExist:
        pass
    return None


# ---------------------------------------------------------------------------
# User serializers
# ---------------------------------------------------------------------------

class AuthenticatedUserSerializer(serializers.ModelSerializer):
    """
    Full identity serializer used by GET /auth/me/.

    Includes:
      - groups           list of group names (for role-based routing)
      - ciso_scope       CISO scope string from CISOProfile, or "" for regular users
      - semantic_colors  user's color preferences, merged with defaults
      - theme            user's active theme name (e.g. "graphite", "future")
      - auto_seasonal    whether seasonal auto-theming is enabled

    Having all appearance fields here means the frontend can fully hydrate
    colors AND the theme from a single /auth/me/ response — no separate
    /profile/ or /profile/colors/ roundtrip needed on page load.
    """
    groups          = serializers.SerializerMethodField()
    ciso_scope      = serializers.SerializerMethodField()
    semantic_colors = serializers.SerializerMethodField()
    theme           = serializers.SerializerMethodField()
    auto_seasonal   = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "groups",
            "ciso_scope",
            "semantic_colors",
            "theme",
            "auto_seasonal",
        )

    def get_groups(self, obj):
        return list(obj.groups.values_list("name", flat=True))

    def get_ciso_scope(self, obj) -> str:
        try:
            return obj.cisoprofile.scope or ""
        except CISOProfile.DoesNotExist:
            return ""

    def get_semantic_colors(self, obj) -> dict:
        profile = _get_profile_for_user(obj)
        if profile is not None:
            return profile.get_semantic_colors()
        return merge_semantic_colors(None)

    def get_theme(self, obj) -> str:
        """
        Returns the user's saved theme name. Falls back to "graphite" if no
        profile exists yet (new user before first profile creation).
        """
        profile = _get_profile_for_user(obj)
        if profile is not None:
            return profile.theme or "graphite"
        return "graphite"

    def get_auto_seasonal(self, obj) -> bool:
        """
        Returns the user's auto_seasonal preference.
        Falls back to False so new users get explicit theme control by default.
        """
        profile = _get_profile_for_user(obj)
        if profile is not None:
            return bool(profile.auto_seasonal)
        return False


class LoginUserSerializer(serializers.ModelSerializer):
    """
    Minimal user representation embedded in the login response.
    Intentionally lighter than AuthenticatedUserSerializer — the login
    response only needs enough to bootstrap the session.
    """
    groups = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "groups",
        )

    def get_groups(self, obj):
        return list(obj.groups.values_list("name", flat=True))


# ---------------------------------------------------------------------------
# Auth serializers
# ---------------------------------------------------------------------------

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        trim_whitespace=True,
        max_length=150,
    )
    password = serializers.CharField(
        trim_whitespace=False,
        write_only=True,
        style={"input_type": "password"},
    )

    default_error_messages = {
        "invalid_credentials": "Invalid credentials.",
        "inactive_account": "User account is disabled.",
    }

    def validate(self, attrs):
        request = self.context.get("request")
        user = authenticate(
            request=request,
            username=attrs["username"],
            password=attrs["password"],
        )

        if user is None:
            raise serializers.ValidationError(
                {"detail": self.error_messages["invalid_credentials"]}
            )
        if not user.is_active:
            raise serializers.ValidationError(
                {"detail": self.error_messages["inactive_account"]}
            )

        attrs["user"] = user
        return attrs


class LoginResponseSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    expiry = serializers.DateTimeField(read_only=True)
    user = LoginUserSerializer(read_only=True)


class LogoutResponseSerializer(serializers.Serializer):
    detail = serializers.CharField(read_only=True)


class MeResponseSerializer(AuthenticatedUserSerializer):
    """
    GET /auth/me/ response — full identity + semantic_colors.
    Subclasses AuthenticatedUserSerializer; no additional fields needed.
    """
    pass