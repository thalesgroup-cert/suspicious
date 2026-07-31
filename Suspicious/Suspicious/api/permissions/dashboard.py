from rest_framework.permissions import BasePermission


class MLRetrainIngestPermission(BasePermission):
    """Restrict AI model retrain-run ingestion (POST) to the dedicated
    service account the retrain pipeline's promote.py authenticates as,
    or staff/superusers. GET (dashboard reads) uses StatsReadPermission
    instead, same as every other stats endpoint.
    """

    allowed_groups = {"ml-retrain"}

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if user.is_staff or user.is_superuser:
            return True

        return user.groups.filter(name__in=self.allowed_groups).exists()


class StatsReadPermission(BasePermission):
    """
    Restrict stats/dashboard endpoints to elevated operational roles.

    Current policy:
    - allow staff/superusers
    - allow users in CISO, CERT, or Admin groups
    - deny everyone else
    """

    allowed_groups = {"CISO", "CERT", "Admin"}

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if user.is_staff or user.is_superuser:
            return True

        return user.groups.filter(name__in=self.allowed_groups).exists()