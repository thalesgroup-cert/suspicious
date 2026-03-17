from rest_framework.permissions import BasePermission


class StatsReadPermission(BasePermission):
    """
    Restrict stats/dashboard endpoints to elevated operational roles.

    Current policy:
    - allow staff/superusers
    - allow users in CISO or CERT groups
    - deny everyone else
    """

    allowed_groups = {"CISO", "CERT"}

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if user.is_staff or user.is_superuser:
            return True

        return user.groups.filter(name__in=self.allowed_groups).exists()