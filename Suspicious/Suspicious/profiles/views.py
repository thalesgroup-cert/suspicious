import logging
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
logger = logging.getLogger(__name__)

from profiles.models import CISOProfile, UserProfile

logger = logging.getLogger(__name__)


def logout_view(request):
    """
    Log out the user and redirect to the login page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponseRedirect: A redirect response to the login page.
    """
    try:
        # Check if the user is authenticated before trying to log them out
        if request.user.is_authenticated:
            logger.info(f"User {request.user} is logging out")
            logout(request)
            logger.info(f"User {request.user} logged out successfully")
        else:
            logger.warning("Unauthenticated user tried to log out")
    except Exception as e:
        logger.error(f"Error logging out user: {str(e)}", exc_info=True)
    # Always redirect to the login page, regardless of whether the logout was successful
    return redirect("login")


# Profile page


@login_required
def profile(request):
    """
    Render the user profile page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered profile page.
    """
    try:
        user = request.user
        user_profile = None
        ciso_profile = None

        # Attempt to retrieve the UserProfile and CISOProfile for the logged-in user
        try:
            user_profile = user.userprofile
        except UserProfile.DoesNotExist:
            logger.info(f"No UserProfile found for user {user.username}")

        try:
            ciso_profile = user.cisoprofile
        except CISOProfile.DoesNotExist:
            logger.info(f"No CISOProfile found for user {user.username}")

        context = {
            "user": user,
            "user_profile": user_profile,
            "ciso_profile": ciso_profile,
        }

        return render(request, "tasp/profile.html", context)
    except Exception as e:
        logger.error(f"Error rendering profile page: {str(e)}", exc_info=True)
        # Optionally, you could redirect to an error page or return an error response here
        return redirect("/")

@csrf_exempt
@login_required
def update_preferences(request):
    """
    Update user preferences via AJAX (JSON).
    """
    try:
        data = json.loads(request.body.decode("utf-8"))

        user = request.user
        user_profile, _ = UserProfile.objects.get_or_create(user=user)

        # Update preferences based on JSON payload
        user_profile.wants_results = bool(data.get("wants_results"))
        user_profile.wants_acknowledgement = bool(data.get("wants_acknowledgement"))
        user_profile.save()

        logger.info(f"Updated preferences for user {user.username}")
        return JsonResponse({"success": True})
    except Exception as e:
        logger.error(f"Error updating preferences: {str(e)}", exc_info=True)
        return JsonResponse(
            {"success": False, "message": "Internal server error"}, status=500
        )

@csrf_exempt
@login_required
def update_appearance(request):
    """
    Update user theme via AJAX (JSON).
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
        theme = data.get("theme")

        if theme not in ["default", "light", "dark", "valentine", "sunrise", "midnight", "cyber"]:
            logger.warning(
                f"Invalid theme '{theme}' submitted by user {request.user.username}"
            )
            return JsonResponse(
                {"success": False, "message": "Invalid theme"}, status=400
            )

        user = request.user
        user_profile, _ = UserProfile.objects.get_or_create(user=user)
        user_profile.theme = theme
        user_profile.save()

        logger.info(f"Updated theme for user {user.username} to {theme}")
        return JsonResponse({"success": True})
    except Exception as e:
        logger.error(f"Error updating appearance: {str(e)}", exc_info=True)
        return JsonResponse(
            {"success": False, "message": "Internal server error"}, status=500
        )
