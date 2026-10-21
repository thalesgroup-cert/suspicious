from django.db.models import Q
from rest_framework.permissions import BasePermission

from api.submissions.constants import SUBMISSION_ELEVATED_GROUPS
from profiles.profiles_utils.scope import scoped_case_queryset

# Elevated groups that see every submission. CISO is elevated too, but only
# inside its own scope (see submission_queryset).
_GLOBAL_GROUPS = frozenset(SUBMISSION_ELEVATED_GROUPS) - {"CISO"}


def user_has_submission_elevated_access(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    return user.groups.filter(name__in=SUBMISSION_ELEVATED_GROUPS).exists()


def submission_queryset(queryset, user):
    """Restrict a Case queryset to the submissions ``user`` may open.

    - CERT/Admin (any elevated group except CISO): every submission.
    - CISO: their own submissions plus those in their scope, resolved by
      ``scoped_case_queryset`` (scope "ALL" = everything, unset scope or
      missing CISOProfile = nothing beyond their own).
    - everyone else: their own submissions only.
    """
    if not user or not user.is_authenticated:
        return queryset.none()
    group_names = set(user.groups.values_list("name", flat=True))
    if group_names & _GLOBAL_GROUPS:
        return queryset
    own = Q(reporter=user)
    if "CISO" in group_names and "CISO" in SUBMISSION_ELEVATED_GROUPS:
        in_scope = scoped_case_queryset(queryset.model.objects.all(), user).values("pk")
        return queryset.filter(own | Q(pk__in=in_scope))
    return queryset.filter(own)


def can_access_submission(user, case) -> bool:
    if case.reporter_id == user.id:
        return True
    return submission_queryset(type(case).objects.filter(pk=case.pk), user).exists()


class CanAccessSubmission(BasePermission):
    """
    Object-level permission (same rule as ``submission_queryset``):
    - reporter can access own submission
    - CERT/Admin can access any submission
    - CISO can access submissions inside their scope
    """

    message = "Not authorized."

    def has_object_permission(self, request, view, obj) -> bool:
        return can_access_submission(request.user, obj)


class CanChallengeSubmission(BasePermission):
    """
    Object-level permission:
    - only reporter can challenge own submission
    """

    message = "Not authorized."

    def has_object_permission(self, request, view, obj) -> bool:
        return obj.reporter_id == request.user.id
