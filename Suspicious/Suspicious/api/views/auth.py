from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from knox.models import AuthToken

from api.serializers.auth import LoginSerializer

class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        groups = list(user.groups.values_list("name", flat=True))

        return Response({
            "id": user.id,
            "username": user.username,
            "email": getattr(user, "email", ""),
            "first_name": getattr(user, "first_name", ""),
            "last_name": getattr(user, "last_name", ""),
            "groups": groups,
            "ciso_scope": "",
        })


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if not user:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        token_instance, token = AuthToken.objects.create(user=user)

        return Response({
            "token": token,
            "expiry": token_instance.expiry,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": getattr(user, "email", ""),
                "groups": list(user.groups.values_list("name", flat=True)),
            },
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        auth = getattr(request, "_auth", None)
        if auth is not None:
            auth.delete()
        return Response({"detail": "Logged out."})