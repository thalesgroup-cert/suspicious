from rest_framework.permissions import BasePermission


class IsAdminOrCERT(BasePermission):
    message = "Admin/CERT only."

    def has_permission(self, request, view) -> bool:
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.groups.filter(name__in=["Admin", "CERT"]).exists()
        )