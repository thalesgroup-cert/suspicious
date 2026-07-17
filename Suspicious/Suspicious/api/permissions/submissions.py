from rest_framework.permissions import BasePermission

from api.submissions.constants import SUBMISSION_ELEVATED_GROUPS


def user_has_submission_elevated_access(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    return user.groups.filter(name__in=SUBMISSION_ELEVATED_GROUPS).exists()


class CanAccessSubmission(BasePermission):
    """
    Object-level permission:
    - reporter can access own submission
    - elevated submission roles can access any submission
    """

    message = "Not authorized."

    def has_object_permission(self, request, view, obj) -> bool:
        return (
            obj.reporter_id == request.user.id
            or user_has_submission_elevated_access(request.user)
        )


class CanChallengeSubmission(BasePermission):
    """
    Object-level permission:
    - only reporter can challenge own submission
    """

    message = "Not authorized."

    def has_object_permission(self, request, view, obj) -> bool:
        return obj.reporter_id == request.user.id