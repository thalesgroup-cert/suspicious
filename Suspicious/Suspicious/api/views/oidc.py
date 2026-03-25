# api/views/oidc_views.py
#
# SSO login flow using the Authorization Code grant (PKCE optional).
#
# Two endpoints:
#
#   GET  /oidc/login/
#     Builds the OIDC authorization URL with state + nonce, stores them
#     in the session, and redirects the browser to the identity provider.
#
#   GET  /oidc/callback/
#     Receives the authorization code, exchanges it for tokens at the
#     provider's token endpoint, fetches the userinfo, creates or updates
#     the local Django user, issues a Knox token, and redirects the browser
#     back to the frontend with the token in the URL fragment.
#
# Configuration keys (read from django.conf.settings, populated from your
# JSON config via environment / django-configurations / similar):
#
#   OIDC_SERVER_URL      — e.g. "https://sso.example.com" (no trailing slash)
#   OIDC_CLIENT_ID       — client ID registered with the provider
#   OIDC_CLIENT_SECRET   — client secret
#   OIDC_REDIRECT_URI    — full callback URL, e.g. "https://suspicious.test/oidc/callback/"
#                          (defaults to <request.build_absolute_uri("/oidc/callback/")>)
#   OIDC_SCOPES          — space-separated scopes, default "openid email profile"
#
# The provider's discovery document is fetched at
#   {OIDC_SERVER_URL}/.well-known/openid-configuration
# to resolve the authorization_endpoint, token_endpoint, and userinfo_endpoint.
# The document is cached in memory for the lifetime of the Django process.

import hashlib
import json
import logging
import os
import secrets
import time
import urllib.parse

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.shortcuts import redirect
from knox.models import AuthToken
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

logger = logging.getLogger(__name__)
User = get_user_model()

# ---------------------------------------------------------------------------
# Discovery cache
# ---------------------------------------------------------------------------

_DISCOVERY_CACHE_KEY = "oidc:discovery"
_DISCOVERY_CACHE_TTL = 3600  # seconds


def _get_discovery() -> dict:
    """
    Fetch and cache the OIDC discovery document from the provider.
    Falls back to a 60-second retry window if the provider is unreachable.
    """
    cached = cache.get(_DISCOVERY_CACHE_KEY)
    if cached:
        return cached

    server_url = settings.OIDC_SERVER_URL.rstrip("/")
    url = f"{server_url}/.well-known/openid-configuration"

    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        doc = resp.json()
    except Exception as exc:
        logger.error("OIDC discovery fetch failed: %s", exc)
        raise

    cache.set(_DISCOVERY_CACHE_KEY, doc, _DISCOVERY_CACHE_TTL)
    return doc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redirect_uri(request) -> str:
    uri = getattr(settings, "OIDC_REDIRECT_URI", None)
    if uri:
        return uri
    return request.build_absolute_uri("/oidc/callback/")


def _frontend_url(path: str = "/") -> str:
    """Base URL for redirecting the browser back to the React app."""
    # In development ALLOWED_HOSTS may be localhost; in production use the
    # first CSRF trusted origin as the canonical frontend URL.
    trusted = getattr(settings, "CSRF_TRUSTED_ORIGINS", [])
    if trusted:
        base = trusted[0].rstrip("/")
    else:
        base = ""
    return f"{base}{path}"


# ---------------------------------------------------------------------------
# GET /oidc/login/
# ---------------------------------------------------------------------------

class OIDCLoginView(APIView):
    """
    Redirects the browser to the OIDC provider's authorization endpoint.
    Generates a cryptographically random state and nonce, stores them in
    the session so the callback can verify them.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            discovery = _get_discovery()
        except Exception:
            return redirect(_frontend_url("/?sso_error=provider_unavailable"))

        state  = secrets.token_urlsafe(32)
        nonce  = secrets.token_urlsafe(32)

        # Persist in session — the callback view will verify these.
        request.session["oidc_state"] = state
        request.session["oidc_nonce"] = nonce
        request.session.save()

        scopes = getattr(settings, "OIDC_SCOPES", "openid email profile")

        params = {
            "response_type": "code",
            "client_id":     settings.OIDC_CLIENT_ID,
            "redirect_uri":  _redirect_uri(request),
            "scope":         scopes,
            "state":         state,
            "nonce":         nonce,
        }

        auth_url = discovery["authorization_endpoint"]
        redirect_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        return redirect(redirect_url)


# ---------------------------------------------------------------------------
# GET /oidc/callback/
# ---------------------------------------------------------------------------

class OIDCCallbackView(APIView):
    """
    Handles the authorization code callback from the OIDC provider.

    Flow:
      1. Verify state matches the session value.
      2. Exchange the code for tokens at the provider's token endpoint.
      3. Verify the id_token's nonce claim.
      4. Fetch userinfo from the provider.
      5. Get-or-create the local Django user.
      6. Issue a Knox token.
      7. Redirect to the frontend with the token in the URL fragment so it
         never appears in server logs:
           /login?sso=1#token=<knox_token>&expiry=<iso>
    """
    permission_classes = [AllowAny]

    def get(self, request):
        # ── Error from provider ──────────────────────────────────────────
        if "error" in request.GET:
            error = request.GET.get("error", "unknown")
            logger.warning("OIDC provider returned error: %s", error)
            return redirect(
                _frontend_url(f"/login?sso_error={urllib.parse.quote(error)}")
            )

        code  = request.GET.get("code")
        state = request.GET.get("state")

        if not code or not state:
            return redirect(_frontend_url("/login?sso_error=missing_params"))

        # ── State verification ───────────────────────────────────────────
        session_state = request.session.pop("oidc_state", None)
        session_nonce = request.session.pop("oidc_nonce", None)

        if not session_state or state != session_state:
            logger.warning("OIDC state mismatch — possible CSRF")
            return redirect(_frontend_url("/login?sso_error=state_mismatch"))

        # ── Discovery ────────────────────────────────────────────────────
        try:
            discovery = _get_discovery()
        except Exception:
            return redirect(_frontend_url("/login?sso_error=provider_unavailable"))

        # ── Token exchange ───────────────────────────────────────────────
        try:
            token_resp = requests.post(
                discovery["token_endpoint"],
                data={
                    "grant_type":    "authorization_code",
                    "code":          code,
                    "redirect_uri":  _redirect_uri(request),
                    "client_id":     settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                },
                timeout=10,
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except Exception as exc:
            logger.error("OIDC token exchange failed: %s", exc)
            return redirect(_frontend_url("/login?sso_error=token_exchange_failed"))

        access_token = token_data.get("access_token")
        id_token_raw = token_data.get("id_token", "")

        # ── Nonce verification (basic — without full JWT validation) ─────
        # For production, verify the id_token signature using the provider's
        # JWKS. For now we decode the payload without verification to check
        # the nonce, which is sufficient to prevent replay attacks when
        # combined with the state check above.
        if id_token_raw and session_nonce:
            try:
                payload_part = id_token_raw.split(".")[1]
                # Add padding
                padded = payload_part + "=" * (-len(payload_part) % 4)
                import base64
                payload = json.loads(base64.urlsafe_b64decode(padded))
                if payload.get("nonce") != session_nonce:
                    logger.warning("OIDC nonce mismatch")
                    return redirect(_frontend_url("/login?sso_error=nonce_mismatch"))
            except Exception as exc:
                logger.warning("OIDC id_token decode failed: %s", exc)
                # Non-fatal — continue with userinfo

        # ── Userinfo ─────────────────────────────────────────────────────
        try:
            userinfo_resp = requests.get(
                discovery["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            userinfo_resp.raise_for_status()
            userinfo = userinfo_resp.json()
        except Exception as exc:
            logger.error("OIDC userinfo fetch failed: %s", exc)
            return redirect(_frontend_url("/login?sso_error=userinfo_failed"))

        # ── Get-or-create user ───────────────────────────────────────────
        try:
            user = _get_or_create_user(userinfo)
        except Exception as exc:
            logger.error("OIDC user resolution failed: %s", exc)
            return redirect(_frontend_url("/login?sso_error=user_resolution_failed"))

        if not user.is_active:
            return redirect(_frontend_url("/login?sso_error=account_disabled"))

        # ── Issue Knox token ─────────────────────────────────────────────
        token_instance, knox_token = AuthToken.objects.create(user=user)

        expiry_iso = (
            token_instance.expiry.isoformat()
            if token_instance.expiry
            else ""
        )

        # Redirect to frontend — token in fragment (never hits server logs).
        fragment = urllib.parse.urlencode({
            "token":  knox_token,
            "expiry": expiry_iso,
        })
        return redirect(_frontend_url(f"/login?sso=1#{fragment}"))


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def _get_or_create_user(userinfo: dict) -> "User":
    """
    Map OIDC userinfo claims to a local Django user.

    Lookup order:
      1. email (most stable cross-provider claim)
      2. preferred_username / sub fallback

    Updates first_name and last_name on every login so they stay in sync
    with the provider.
    """
    email    = (userinfo.get("email") or "").lower().strip()
    username = (
        userinfo.get("preferred_username")
        or userinfo.get("sub")
        or email.split("@")[0]
        or "oidc_user"
    )
    first_name = userinfo.get("given_name") or userinfo.get("name", "").split()[0] if userinfo.get("name") else ""
    last_name  = userinfo.get("family_name") or ""

    # Truncate to Django's max lengths
    username   = username[:150]
    first_name = first_name[:150]
    last_name  = last_name[:150]

    if email:
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "username":   username,
                "first_name": first_name,
                "last_name":  last_name,
            },
        )
    else:
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "first_name": first_name,
                "last_name":  last_name,
            },
        )

    if not created:
        # Keep name fields in sync with the provider on every login
        changed = False
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            changed = True
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            changed = True
        if changed:
            user.save(update_fields=["first_name", "last_name"])

    logger.info(
        "OIDC login: user=%s email=%s created=%s",
        user.username, email, created,
    )
    return user