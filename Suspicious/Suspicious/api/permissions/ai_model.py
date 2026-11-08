from rest_framework.permissions import BasePermission


# A superuser without the Admin group is refused on purpose: Ruling F14 follows IsAdminOrCERT, group only.
class _InGroups(BasePermission):
    groups: tuple = ()

    def has_permission(self, request, view) -> bool:
        user = request.user
        return bool(user and user.is_authenticated and user.groups.filter(name__in=self.groups).exists())


class IsAdmin(_InGroups):
    """Writes of the AI model card (Ruling F14)."""

    message = "Admin only."
    groups = ("Admin",)


class IsAdminOrCISO(_InGroups):
    """Reads of the AI model card (Ruling F14)."""

    message = "Admin/CISO only."
    groups = ("Admin", "CISO")
