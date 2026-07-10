from django.conf import settings
from knox.models import AuthToken
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics, permissions, status, throttling
from rest_framework.response import Response

from api.authentication import KNOX_COOKIE_NAME, SESSION_INDICATOR_COOKIE
from api.serializers.auth import (
    LoginResponseSerializer,
    LoginSerializer,
    LogoutResponseSerializer,
    MeResponseSerializer,
)


def _set_auth_cookies(response, token: str, max_age: int, secure: bool) -> None:
    """Set the httpOnly token cookie and the JS-readable session indicator."""
    response.set_cookie(
        KNOX_COOKIE_NAME,
        token,
        httponly=True,
        secure=secure,
        samesite="Strict",
        max_age=max_age,
        path="/",
    )
    response.set_cookie(
        SESSION_INDICATOR_COOKIE,
        "1",
        httponly=False,
        secure=secure,
        samesite="Strict",
        max_age=max_age,
        path="/",
    )


def _clear_auth_cookies(response) -> None:
    """Clear both auth cookies on logout."""
    response.delete_cookie(KNOX_COOKIE_NAME, path="/", samesite="Strict")
    response.delete_cookie(SESSION_INDICATOR_COOKIE, path="/", samesite="Strict")


class LoginRateThrottle(throttling.AnonRateThrottle):
    scope = "login"


class MeView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MeResponseSerializer

    @extend_schema(
        operation_id="auth_me",
        responses={
            200: MeResponseSerializer,
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
        },
        tags=["auth"],
    )
    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LoginView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer
    throttle_classes = [LoginRateThrottle]

    @extend_schema(
        operation_id="auth_login",
        request=LoginSerializer,
        responses={
            200: LoginResponseSerializer,
            400: OpenApiResponse(description="Invalid request payload."),
            401: OpenApiResponse(description="Invalid credentials."),
            429: OpenApiResponse(description="Too many login attempts."),
        },
        tags=["auth"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        token_instance, token = AuthToken.objects.create(user=user)

        response_data = {
            "token": token,
            "expiry": token_instance.expiry,
            "user": user,
        }

        ttl = settings.REST_KNOX.get("TOKEN_TTL")
        max_age = int(ttl.total_seconds()) if ttl else 36_000

        response = Response(
            LoginResponseSerializer(response_data).data,
            status=status.HTTP_200_OK,
        )
        _set_auth_cookies(response, token, max_age, secure=not settings.DEBUG)
        return response


class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutResponseSerializer

    @extend_schema(
        operation_id="auth_logout",
        request=None,
        responses={
            200: LogoutResponseSerializer,
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
        },
        tags=["auth"],
    )
    def post(self, request, *args, **kwargs):
        token = request.auth
        if token is not None:
            token.delete()

        response = Response({"detail": "Logged out."}, status=status.HTTP_200_OK)
        _clear_auth_cookies(response)
        return response