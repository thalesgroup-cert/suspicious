from knox.models import AuthToken
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics, permissions, serializers, status, throttling
from rest_framework.response import Response

from api.serializers.auth import (
    LoginResponseSerializer,
    LoginSerializer,
    LogoutResponseSerializer,
    MeResponseSerializer,
)


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

        return Response(
            LoginResponseSerializer(response_data).data,
            status=status.HTTP_200_OK,
        )


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

        return Response(
            {"detail": "Logged out."},
            status=status.HTTP_200_OK,
        )