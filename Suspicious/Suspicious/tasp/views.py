# Python Standard Library Imports
import base64
import hashlib
import json
import logging
from functools import lru_cache
from typing import Callable, Dict
from urllib.parse import urlencode, urljoin

# Django Core Imports
import django
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.db import transaction, IntegrityError
from django.db.models import Q, QuerySet, F
from django.http import JsonResponse, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_GET

# Local Application/Project Imports

from tasp.forms import UploadFileForm, UploadURLForm, UploadOtherForm
from tasp.utils.popup import generate_html

import jwt
import requests

from case_handler.case_utils.case_handler import CaseHandler
from case_handler.models import Case
from case_handler.update_case.update_handler import (
    handle_attachment,
    handle_artifact,
    handle_mail,
    handle_file,
    handle_ioc,
)
from score_process.score_utils.send_mail.service import MailNotificationService

from cortex_job.models import AnalyzerReport

from profiles.models import CISOProfile
from tasp.services.challenge import run_case_challenge

# --- Constants ---
ERROR_CASE_NOT_FOUND = "Case does not exist."
ERROR_INVALID_PARAMETERS = "Invalid input parameters provided."
ERROR_JSON_DECODING = "Error decoding JSON file."
ERROR_NO_ANALYZER_DATA_FOUND = "No analyzer data found for the given IOC."
ERROR_INVALID_REQUEST_METHOD = "Invalid request method."
ERROR_INVALID_LEVEL_FORMAT = "Invalid format for level. It must be an integer."
ERROR_UNEXPECTED = "An unexpected error occurred. Please try again later."
# ALLOWED_IOC_TYPES_ANALYZER = ['attachment', 'artifact', 'body', 'header'] # For stricter validation


CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get("suspicious", {})

# Email configuration (safer to get from Django settings or handle None)
EMAIL_SENDER_DEFAULT = suspicious_config.get("email", "SUSPICIOUS")

CSV_CONTENT_TYPE = "text/csv"
JSON_CONTENT_TYPE = "application/json"
TXT_CONTENT_TYPE = "text/plain"
CASE_NOT_EXIST_ERROR = "Case does not exist"
JSON_DECODING_ERROR = "Error decoding JSON file."
INVALID_REQUEST_OR_NO_FILE_ERROR = "Invalid request method or no file uploaded."
INVALID_PARAMETER_ERROR = "Invalid parameter"
INVALID_FILETYPE_ERROR = "Invalid file type."
INVALID_TYPE_ERROR = "Invalid type"
CSV = "csv"
JSON = "json"
TXT = "txt"


ERROR_MISSING_PARAMETERS = "Missing required parameter."
ERROR_UNSUPPORTED_IOC_TYPE = "Invalid IOC type."

IOC_HANDLER_MAP: Dict[str, Callable] = {
    "attachment": handle_attachment,
    "artifact": handle_artifact,
    "body": handle_mail,
    "header": handle_mail,
    "file": handle_file,
    "ip": handle_ioc,
    "url": handle_ioc,
    "hash": handle_ioc,
}
IOC_TYPES_NEEDING_TYPE_ARG = {"body", "header", "ip", "url", "hash"}

# --- Logger Configuration ---
logger = logging.getLogger(__name__)


def _oidc_enabled() -> bool:
    return bool(
        settings.OIDC_SERVER_URL
        and settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
    )


@lru_cache(maxsize=1)
def _get_oidc_provider_config() -> Dict[str, str]:
    discovery_url = urljoin(
        settings.OIDC_SERVER_URL.rstrip("/") + "/",
        ".well-known/openid-configuration",
    )
    response = requests.get(discovery_url, timeout=10)
    response.raise_for_status()
    return response.json()


def _generate_pkce_pair() -> Dict[str, str]:
    code_verifier = get_random_string(64)
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge_b64 = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("utf-8")
    return {"code_verifier": code_verifier, "code_challenge": code_challenge_b64}


def _build_safe_next_url(request: HttpRequest) -> str:
    next_url = request.GET.get("next")
    if next_url and url_has_allowed_host_and_scheme(
        next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return next_url
    return ""


def oidc_login(request: HttpRequest) -> HttpResponseRedirect:
    if not _oidc_enabled():
        messages.error(request, "Company SSO is not configured.")
        return redirect("login")

    try:
        provider_config = _get_oidc_provider_config()
    except requests.RequestException as exc:
        logger.error("OIDC discovery failed: %s", exc, exc_info=True)
        messages.error(request, "Unable to reach the SSO provider.")
        return redirect("login")

    state = get_random_string(32)
    nonce = get_random_string(32)
    pkce_pair = _generate_pkce_pair()
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce
    request.session["oidc_code_verifier"] = pkce_pair["code_verifier"]
    request.session["oidc_next"] = _build_safe_next_url(request)

    redirect_uri = request.build_absolute_uri(reverse("tasp:oidc_callback"))
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": settings.OIDC_SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_pair["code_challenge"],
        "code_challenge_method": "S256",
    }
    authorization_url = f"{provider_config['authorization_endpoint']}?{urlencode(params)}"
    return redirect(authorization_url)


def oidc_callback(request: HttpRequest) -> HttpResponseRedirect:
    if not _oidc_enabled():
        messages.error(request, "Company SSO is not configured.")
        return redirect("login")

    error = request.GET.get("error")
    if error:
        messages.error(request, f"SSO error: {error}")
        return redirect("login")

    state = request.GET.get("state")
    if not state or state != request.session.get("oidc_state"):
        messages.error(request, "Invalid SSO response.")
        return redirect("login")

    code = request.GET.get("code")
    if not code:
        messages.error(request, "Missing authorization code.")
        return redirect("login")

    try:
        provider_config = _get_oidc_provider_config()
    except requests.RequestException as exc:
        logger.error("OIDC discovery failed: %s", exc, exc_info=True)
        messages.error(request, "Unable to reach the SSO provider.")
        return redirect("login")

    redirect_uri = request.build_absolute_uri(reverse("tasp:oidc_callback"))
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.OIDC_CLIENT_ID,
        "code_verifier": request.session.get("oidc_code_verifier", ""),
    }
    try:
        token_response = requests.post(
            provider_config["token_endpoint"],
            data=token_payload,
            auth=(settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET),
            timeout=10,
        )
        token_response.raise_for_status()
    except requests.RequestException as exc:
        logger.error("OIDC token exchange failed: %s", exc, exc_info=True)
        messages.error(request, "SSO token exchange failed.")
        return redirect("login")

    token_data = token_response.json()
    id_token = token_data.get("id_token")
    if not id_token:
        messages.error(request, "SSO response did not include an ID token.")
        return redirect("login")

    try:
        jwk_client = jwt.PyJWKClient(provider_config["jwks_uri"])
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        algorithms = provider_config.get("id_token_signing_alg_values_supported", ["RS256"])
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=algorithms,
            audience=settings.OIDC_CLIENT_ID,
            issuer=provider_config["issuer"],
        )
    except jwt.PyJWTError as exc:
        logger.error("OIDC ID token validation failed: %s", exc, exc_info=True)
        messages.error(request, "Invalid SSO ID token.")
        return redirect("login")

    nonce = request.session.get("oidc_nonce")
    if nonce and claims.get("nonce") != nonce:
        messages.error(request, "Invalid SSO nonce.")
        return redirect("login")

    email = claims.get("email")
    if not email:
        messages.error(request, "SSO account missing email.")
        return redirect("login")

    user_defaults = {
        "email": email,
        "first_name": claims.get("given_name", ""),
        "last_name": claims.get("family_name", ""),
    }
    user, _created = User.objects.get_or_create(username=email, defaults=user_defaults)
    if not user.is_active:
        messages.error(request, "Your account is inactive.")
        return redirect("login")

    for field, value in user_defaults.items():
        if value and getattr(user, field) != value:
            setattr(user, field, value)
    user.save(update_fields=["email", "first_name", "last_name"])

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session.pop("oidc_state", None)
    request.session.pop("oidc_nonce", None)
    request.session.pop("oidc_code_verifier", None)
    next_url = request.session.pop("oidc_next", "")
    if next_url:
        return redirect(next_url)
    return redirect("tasp:home")


# --- Authentication Views ---
@require_GET
@csrf_protect
def logout_view(request: HttpRequest) -> HttpResponseRedirect:
    """
    Log out the user and redirect to the login page.
    Ensures logout is done via POST and handles cases where user might not be authenticated.
    """
    user_display = str(request.user)
    try:
        if request.user.is_authenticated:
            logout(request)
            logger.info(f"User '{user_display}' logged out successfully.")
        else:
            logger.warning("Attempt to logout by an unauthenticated user.")
    except Exception as e:
        logger.error(
            f"Error during logout for user '{user_display}': {e}", exc_info=True
        )
    return redirect("login")


# --- Page Views ---
@login_required
@require_GET
def home(request: HttpRequest) -> HttpResponse:
    """Render the home page, potentially showing a modal based on CISOProfile."""
    context = {"show_modal": False, "user_groups": request.user.groups.all()}
    try:
        user_profile = CISOProfile.objects.get(user=request.user)
        if (
            user_profile.scope == "Not defined"
        ):  # Consider making 'Not defined' a constant
            context["show_modal"] = True
    except CISOProfile.DoesNotExist:
        logger.debug(
            f"CISOProfile does not exist for user '{request.user}'. Modal not shown."
        )
    except Exception as e:  # Catch other potential errors during profile access
        logger.error(
            f"Error fetching CISOProfile for user '{request.user}': {e}", exc_info=True
        )

    logger.info(f"User '{request.user}' accessed home page.")
    return render(request, "home.html", context)


@login_required
@require_GET
def submissions(request: HttpRequest) -> HttpResponse:
    """Render the submissions page displaying the user's latest cases."""
    context = {}
    try:
        latest_cases = Case.objects.filter(reporter=request.user).order_by(
            "-creation_date"
        )
        if latest_cases:
            context["latest_cases"] = latest_cases
        logger.info(
            f"User '{request.user}' accessed submissions page. Found {latest_cases.count()} cases."
        )
    except django.db.Error as e:
        logger.error(
            f"Database error fetching cases for user '{request.user}': {e}",
            exc_info=True,
        )
    except Exception as e:
        logger.error(
            f"Unexpected error fetching cases for user '{request.user}': {e}",
            exc_info=True,
        )
    return render(request, "tasp/index.html", context)


def _get_admin_cases(user: User) -> Q:
    """Helper to construct the Q object for filtering cases for admins/CERT based on scope.
    Restricts to reporters who belong to all groups defined in scope.
    """
    user_profile = CISOProfile.objects.filter(user=user).first()
    query = Q()

    if user_profile and user_profile.scope and user_profile.scope != "Not defined":
        group_names = [g.strip() for g in user_profile.scope.split("|") if g.strip()]
        if group_names:
            users_in_scope = User.objects.all()
            for g in group_names:
                users_in_scope = users_in_scope.filter(groups__name=g)
            query = Q(reporter__in=users_in_scope)
    return query



@login_required
@require_GET
def tasp(request):
    try:
        service = TaspService(request.user)
        latest_cases = service.get_latest_cases()
    except Exception as e:
        logger.error(f"Unexpected error on TASP page for user '{request.user}': {e}", exc_info=True)
        latest_cases = Case.objects.none()

    return render(request, "tasp/tasp.html", {"latest_cases": latest_cases})


class TaspService:
    def __init__(self, user):
        self.user = user
        self.seven_days_ago = timezone.now() - timezone.timedelta(days=7)

    def is_admin_or_cert(self) -> bool:
        return (
            self.user.is_superuser
            or self.user.groups.filter(name__in=["Admin", "CERT", "Champions"]).exists()
        )

    def get_ciso_profile(self):
        return CISOProfile.objects.filter(user=self.user).exists()

    def get_cases_for_admin(self):
        query = Q(creation_date__gte=self.seven_days_ago)
        return Case.objects.filter(query).order_by("-creation_date")

    def get_cases_for_ciso(self):
        scope_query = _get_admin_cases(self.user)
        if scope_query:
            return Case.objects.filter(scope_query, creation_date__gte=self.seven_days_ago).order_by("-creation_date")
        return Case.objects.none()

    def get_latest_cases(self):
        if self.is_admin_or_cert():
            cases = self.get_cases_for_admin()
            logger.info(f"Admin/CERT user '{self.user}' accessed TASP page. Found {cases.count()} cases.")
            return cases

        ciso_profile = self.get_ciso_profile()
        if ciso_profile:
            cases = self.get_cases_for_ciso()
            logger.info(f"CISO user '{self.user}' accessed TASP page. Found {cases.count()} cases.")
            return cases

        logger.warning(f"User '{self.user}' without sufficient permissions attempted to access TASP page.")
        return Case.objects.none()


# --- API-like Views (Modifying Data) ---


@login_required
@csrf_protect
@transaction.atomic
def edit_global(request: HttpRequest, case_id: int, score: float, confidence: float, classification: str) -> JsonResponse:
    old_status = ""
    try:
        case = Case.objects.get(id=case_id)
        old_status = case.results
    except Case.DoesNotExist:
        return JsonResponse({"success": False, "error": "Case does not exist"}, status=404)

    if old_status == classification:
        return JsonResponse({"success": True, "message": "Case results is the same", "score": case.finalScore, "confidence": case.finalConfidence, "classification": classification})

    service = CaseEditService(case, logger)
    try:
        service.update_global_attributes(score, confidence, classification, request.user)
    except ValueError as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)

    try:

        service.notify_reporter()
    except Exception as e:
        logger.error(f"Failed to send modification email for case ID {case.id}: {e}", exc_info=True)

    logger.info(f"User '{request.user}' edited case {case.id}")
    return JsonResponse({
        "success": True,
        "score": case.finalScore,
        "confidence": case.finalConfidence,
        "classification": classification
    })


class CaseEditService:
    def __init__(self, case, logger):
        self.case = case
        self.logger = logger

    def update_global_attributes(self, score, confidence, classification, updated_by):
        try:
            self.case.finalScore = float(score)
            self.case.finalConfidence = float(confidence)
        except (TypeError, ValueError):
            raise ValueError("Score and confidence must be valid floats")

        self.case.results = classification
        self.case.last_update_by = updated_by

        if self.case.status == CaseStatus.CHALLENGED:
            self.case.status = CaseStatus.DONE

        self.case.save(update_fields=["finalScore", "finalConfidence", "results", "last_update_by", "status"])

    def notify_reporter(self):
        cls = MailNotificationService.from_settings()
        cls.send_review_email(self.case)
        self.logger.info(f"Modification email sent for case ID {self.case.id} to '{self.case.reporter}'.")

class CaseStatus():
    CHALLENGED = "Challenged"
    DONE = "Done"


@login_required
@csrf_protect
@transaction.atomic
def challenge(request: HttpRequest, case_id: int) -> JsonResponse:
    try:
        case = _get_case_or_404(case_id, request.user)

        run_case_challenge(case, logger)

        return JsonResponse({"success": True, "message": f"Case {case_id} successfully challenged."})

    except ValueError as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)
    except Case.DoesNotExist:
        return JsonResponse({"success": False, "error": ERROR_CASE_NOT_FOUND}, status=404)
    except IntegrityError:
        logger.exception(f"Database integrity error for case {case_id}")
        return JsonResponse({"success": False, "error": "Database error processing challenge."}, status=500)
    except Exception:
        logger.exception(f"Unexpected error for case {case_id}")
        return JsonResponse({"success": False, "error": ERROR_UNEXPECTED}, status=500)


def _get_case_or_404(case_id, user):
    return get_object_or_404(
        Case.objects.select_related("reporter"),
        id=case_id,
        reporter=user
    )


# --- Pop-up View ---
@login_required
@require_GET
def create_case_popup(request: HttpRequest, case_id: int, user: str) -> JsonResponse:
    """
    Generates and returns HTML for a case details pop-up.
    Ensures the requesting user is the reporter or has specific permission to view.

    Args:
        request: The HTTP request object.
        case_id: The ID of the case for which to generate the pop-up.
        The 'user' (username) parameter from URL is removed for security;
        authorization is based on request.user.
    """
    try:
        case = get_object_or_404(Case.objects.select_related("reporter"), id=case_id)

        is_admin_or_cert = (
            request.user.is_superuser
            or request.user.groups.filter(name__in=["Admin", "CERT", "Champions"]).exists()
        )
        is_ciso = CISOProfile.objects.filter(user=request.user).first()

        # If user is Admin/CERT, they can view any case pop-up.
        if is_admin_or_cert:
            can_view_any_popup = True
        # If user is CISO, check if they have a profile with a defined scope.
        elif is_ciso:
            can_view_any_popup = is_ciso.scope != "Not defined"
        else:
            can_view_any_popup = False
        if not (request.user == case.reporter or can_view_any_popup):
            logger.warning(
                f"User '{request.user}' denied access to popup for case ID {case.id} "
                f"owned by '{case.reporter}'."
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Permission denied to view this case pop-up.",
                },
                status=403,
            )

        html_content = generate_html(case)
        logger.info(f"User '{request.user}' accessed pop-up for case ID {case.id}.")
        return JsonResponse({"success": True, "html": html_content})

    except Case.DoesNotExist:
        logger.warning(
            f"Case pop-up requested for non-existent case ID {case_id} by user '{request.user}'."
        )
        return JsonResponse(
            {"success": False, "error": ERROR_CASE_NOT_FOUND}, status=404
        )
    except Exception as e:
        logger.error(
            f"Error generating pop-up for case ID {case_id} for user '{request.user}': {e}",
            exc_info=True,
        )
        return JsonResponse(
            {"success": False, "error": "Failed to generate case pop-up."}, status=500
        )


# --- Submission View ---
@login_required
def submit(request):
    """
    Handle the submission of new cases (file, URL, IP/hash, or email).
    Utilizes CaseHandler to validate inputs, process submissions,
    launch analysis if needed, and create cases.
    """
    file_form = UploadFileForm(request.POST or None, request.FILES or None)
    url_form = UploadURLForm(request.POST or None)
    other_form = UploadOtherForm(request.POST or None)

    if request.method == "POST":
        logger.info("User '%s' submitted a case", request.user)
        handler = CaseHandler(request, file_form, url_form, other_form)
        results = handler.validate_forms()
        logger.debug("Validation results: %s", results)

        # Unpack results
        file_inst = results["file_instance"]
        mail_inst = results["mail_instance"]
        ip_inst = results["ip_instance"]
        url_inst = results["url_instance"]
        hash_inst = results["hash_instance"]
        allow_listed = results["allow_listed"]

        # Ensure we have something to process
        if any([file_inst, ip_inst, url_inst, hash_inst]):
            # Attempt case creation
            case = handler.handle_case(
                file_inst=file_inst,
                mail_inst=mail_inst,
                ip_inst=ip_inst,
                url_inst=url_inst,
                hash_inst=hash_inst,
                allow_listed=allow_listed,
            )
            if case:
                msg_type = "email file" if mail_inst else "indicator/file"
                logger.info("Case created by '%s' (type: %s).", request.user, msg_type)
                messages.success(request, "Case submitted successfully.")
                return redirect("tasp:submissions")

            logger.error("Case creation failed unexpectedly for user '%s'.", request.user)
            messages.error(request, "Submission failed during processing. Please try again.")
        elif mail_inst:
            logger.info("Email case submitted by '%s'.", request.user)
            return redirect("tasp:submissions")
        else:
            # No actionable input or forms invalid
            if file_form.errors or url_form.errors or other_form.errors:
                logger.warning("Form errors on submission by '%s': file %s, url %s, other %s",
                               request.user, file_form.errors, url_form.errors, other_form.errors)
                messages.error(request, "Please correct the highlighted form errors.")
            else:
                logger.warning("Empty or invalid submission by '%s'.", request.user)
                messages.warning(request, "No data provided. Please fill at least one form field.")

    else:
        logger.info("User '%s' accessed submission page.", request.user)

    context = {
        "form": file_form,
        "formurl": url_form,
        "otherform": other_form,
    }
    return render(request, "tasp/submit.html", context)


# --- Static Page View ---
@login_required
@require_GET
def about(request: HttpRequest) -> HttpResponse:
    """Render the about page."""
    logger.info(f"User '{request.user}' accessed the about page.")
    return render(request, "tasp/about.html")


@login_required
@require_GET  # This endpoint retrieves data, so GET is appropriate.
def get_link_analyzer(request: HttpRequest, value: str, ioc_type: str) -> JsonResponse:
    """
    Retrieves and returns a list of analyzer report details based on the provided
    IOC value and type.

    Args:
        request: The HTTP request object.
        value: The IOC value to search for.
        ioc_type: The type of IOC (e.g., 'attachment', 'artifact', 'body', 'header').

    Returns:
        JsonResponse: Contains a list of analyzer reports if found,
                    or an error message.
    """
    if not value or not ioc_type:
        logger.warning(
            f"User '{request.user}' called get_link_analyzer with missing value or ioc_type."
        )
        return JsonResponse(
            {"success": False, "error": ERROR_INVALID_PARAMETERS}, status=400
        )

    cleaned_ioc_type = ioc_type.strip().replace('"', "").lower()
    if not cleaned_ioc_type:
        logger.warning(
            f"User '{request.user}' provided an empty or invalid ioc_type after cleaning: '{ioc_type}'."
        )
        return JsonResponse(
            {"success": False, "error": ERROR_INVALID_PARAMETERS}, status=400
        )

    analyzer_reports_qs: QuerySet[AnalyzerReport] = AnalyzerReport.objects.none()

    try:
        base_query = AnalyzerReport.objects.select_related("analyzer")

        if cleaned_ioc_type == "attachment":
            analyzer_reports_qs = base_query.filter(file__linked_hash__value=value)
        elif cleaned_ioc_type == "artifact":
            analyzer_reports_qs = base_query.filter(
                Q(ip__address=value) | Q(url__address=value) | Q(hash__value=value)
            ).distinct()
        elif cleaned_ioc_type == "body":
            analyzer_reports_qs = base_query.filter(mail_body__fuzzy_hash=value)
        elif cleaned_ioc_type == "header":
            analyzer_reports_qs = base_query.filter(mail_header__fuzzy_hash=value)
        else:
            logger.warning(
                f"User '{request.user}' provided an unsupported ioc_type: '{cleaned_ioc_type}'."
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": f"Unsupported IOC type: {cleaned_ioc_type}",
                },
                status=400,
            )

        if not analyzer_reports_qs.exists():
            logger.info(
                f"No analyzer reports found for user '{request.user}', value: '{value}', ioc_type: '{cleaned_ioc_type}'."
            )
            return JsonResponse(
                {"success": False, "error": ERROR_NO_ANALYZER_DATA_FOUND}, status=404
            )

        reports_data = []
        for report in analyzer_reports_qs:
            analyzer_name = (
                report.analyzer.name if report.analyzer else "Unknown Analyzer"
            )
            reports_data.append(
                {
                    "analyzer_name": analyzer_name,
                    "score": report.score,
                    "confidence": report.confidence,
                    "level": report.level,
                    "category": report.get_category(),
                    "summary": report.report_summary,
                }
            )

        logger.info(
            f"Successfully retrieved {len(reports_data)} analyzer report(s) for user '{request.user}', "
            f"value: '{value}', ioc_type: '{cleaned_ioc_type}'."
        )
        return JsonResponse({"success": True, "reports": reports_data})

    except django.db.Error as db_e:
        logger.error(
            f"Database error retrieving analyzer data for user '{request.user}', value: '{value}', ioc_type: '{cleaned_ioc_type}': {db_e}",
            exc_info=True,
        )
        return JsonResponse(
            {"success": False, "error": "A database error occurred."}, status=500
        )
    except AttributeError as attr_e:
        logger.error(
            f"Attribute error processing analyzer data for user '{request.user}', value: '{value}', ioc_type: '{cleaned_ioc_type}': {attr_e}",
            exc_info=True,
        )
        return JsonResponse(
            {"success": False, "error": "Error processing report data."}, status=500
        )
    except Exception as e:
        logger.error(
            f"Unexpected error retrieving analyzer data for user '{request.user}', value: '{value}', ioc_type: '{cleaned_ioc_type}': {e}",
            exc_info=True,
        )
        return JsonResponse({"success": False, "error": ERROR_UNEXPECTED}, status=500)


@login_required
@csrf_protect
def set_ioc_level(request: HttpRequest, id, type, level, case_id) -> JsonResponse:
    """
    Update the IOC level for a given IOC ID and type.
    Expects POST with: ioc_id, ioc_type, level, case_id
    """
    try:
        KEY_IOC_ID = "ioc_id"
        KEY_IOC_TYPE = "ioc_type"
        KEY_LEVEL = "level"
        KEY_CASE_ID = "case_id"
        # Extract POST params
        ioc_id_str = str(id)
        ioc_type = type
        level_str = level
        case_id_str = int(case_id)

        if not all([ioc_id_str, ioc_type, level_str, case_id_str]):
            logger.warning(
                f"User={request.user} missing params: "
                f"{KEY_IOC_ID}={ioc_id_str}, {KEY_IOC_TYPE}={ioc_type}, "
                f"{KEY_LEVEL}={level_str}, {KEY_CASE_ID}={case_id_str}"
            )
            return JsonResponse(
                {"success": False, "error": ERROR_MISSING_PARAMETERS}, status=400
            )

        # Validate ints
        try:
            ioc_id, level, case_id = str(ioc_id_str), str(level_str), int(case_id_str)
        except ValueError:
            logger.warning(
                f"User={request.user} provided invalid numeric values: "
                f"ioc_id={ioc_id_str}, level={level_str}, case_id={case_id_str}"
            )
            return JsonResponse(
                {"success": False, "error": ERROR_INVALID_LEVEL_FORMAT}, status=400
            )

        # Resolve handler
        handler_func = IOC_HANDLER_MAP.get(ioc_type)
        if not handler_func:
            logger.warning(f"User={request.user} invalid ioc_type='{ioc_type}'")
            return JsonResponse(
                {"success": False, "error": ERROR_UNSUPPORTED_IOC_TYPE}, status=400
            )

        logger.info(
            f"User={request.user} updating IOC id={ioc_id}, type={ioc_type}, "
            f"level={level}, case_id={case_id}"
        )

        # Dispatch to handler
        if ioc_type in IOC_TYPES_NEEDING_TYPE_ARG:
            response = handler_func(ioc_id, ioc_type, level, case_id)
        else:
            response = handler_func(ioc_id, level, case_id)

        # Validate response
        if not isinstance(response, JsonResponse):
            logger.error(
                f"Handler for type={ioc_type} returned invalid response (not JsonResponse)"
            )
            return JsonResponse(
                {"success": False, "error": "Internal handler error."}, status=500
            )

        return response

    except Exception as e:
        logger.critical(
            f"Unexpected error in set_ioc_level for user={request.user}: {e}",
            exc_info=True,
        )
        return JsonResponse({"success": False, "error": ERROR_UNEXPECTED}, status=500)

@csrf_exempt
def update_ciso_profile_scope(request, scope):
    """Update the CISO profile scope.

    This function updates the scope of the CISO profile for the current user.

    Args:
        request (HttpRequest): The HTTP request object.
        scope (str): The new scope value to be set for the CISO profile.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the update operation.

    Raises:
        None

    """
    SUCCESS_MESSAGE = "CISO profile scope updated successfully."
    NOT_FOUND_MESSAGE = "CISO profile not found."

    try:
        user_profile = CISOProfile.objects.get(user=request.user)
        user_profile.scope = scope
        user_profile.save()
        logger.info(
            f"CISO profile scope updated to '{scope}' for user '{request.user}'."
        )
        return JsonResponse({"success": True, "message": SUCCESS_MESSAGE})
    except CISOProfile.DoesNotExist:
        logger.warning(f"CISO profile not found for user '{request.user}'.")
        return JsonResponse({"success": False, "error": NOT_FOUND_MESSAGE}, status=404)


@csrf_exempt
def compute(request, id, user):
    """Compute function to retrieve analysis information for a given case.

    Args:
        request (HttpRequest): The HTTP request object.
        id (int): The ID of the case.
        user (str): The username of the user.

    Returns:
        JsonResponse: A JSON response containing the analysis information for the case.

    Raises:
        ValueError: If the provided case ID is invalid.
        Exception: If an error occurs while retrieving the analysis information.
    """
    try:
        case_id = int(id)
    except ValueError as e:
        logger.warning(f"Invalid case id: {id}")
        return JsonResponse({"success": False, "error": str(e)})

    case = Case.objects.filter(id=case_id).first()
    if not case:
        logger.warning(f"Case {case_id} not found")
        return JsonResponse({"success": False, "error": CASE_NOT_EXIST_ERROR})

    if case.reporter and str(case.reporter) == user:
        # CortexJobManager().manage_jobs(case)
        logger.info(f"Analysis infos retrieved successfully for case {case_id}")
        context = {
            "analysis_done": case.analysis_done,
            "status": case.status,
            "results": case.results,
            "case_score": case.finalScore,
            "confidence": case.finalConfidence,
        }
        logger.info(f"Analysis done retrieved successfully for case {case_id}")
        return JsonResponse({"success": True, "context": context})
    else:
        logger.warning(f"Case {case_id} not found")
        return JsonResponse({"success": False, "error": "Case not found"})
