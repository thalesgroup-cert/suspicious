from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers


User = get_user_model()


class AuthenticatedUserSerializer(serializers.ModelSerializer):
    groups = serializers.SerializerMethodField()
    ciso_scope = serializers.CharField(read_only=True, default="")

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
        )

    def get_groups(self, obj):
        return list(obj.groups.values_list("name", flat=True))


class LoginUserSerializer(serializers.ModelSerializer):
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
        username = attrs["username"]
        password = attrs["password"]

        user = authenticate(request=request, username=username, password=password)
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
    pass