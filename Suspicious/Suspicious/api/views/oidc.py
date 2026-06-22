#
# OIDC Authorization Code flow with:
#   • PKCE (S256)                    — prevents auth code interception
#   • Full JWT signature validation  — verifies id_token against provider JWKS
#   • HTTP Basic auth at token endpoint — spec-compliant client authentication
#   • State + nonce binding          — prevents CSRF and replay attacks
#   • Knox token issuance            — integrates with the DRF token auth system
#
# Two endpoints:
#
#   GET /api/oidc/login/
#     Generates state, nonce, and PKCE pair; stores them in the session;
#     redirects the browser to the provider's authorization endpoint.
#
#   GET /api/oidc/callback/
#     Verifies state, exchanges the code (with code_verifier), validates the
#     id_token signature and nonce via PyJWT + JWKS, gets or creates the
#     local Django user, issues a Knox token, and redirects the React SPA
#     to /login?sso=1#token=<knox>&expiry=<iso>.
#     The token is in the URL fragment — it never appears in server access logs.
#
# Required Django settings (populated from settings.json):
#   OIDC_SERVER_URL      — IdP base URL, e.g. "https://sso.corp.example"
#   OIDC_CLIENT_ID       — registered client ID
#   OIDC_CLIENT_SECRET   — registered client secret
#   OIDC_SCOPES          — space-separated scopes (default: "openid email profile")
#
# Optional:
#   OIDC_REDIRECT_URI    — explicit callback URL override (auto-derived if absent)
#
# Dependencies:
#   pip install PyJWT[cryptography] requests

import base64
import hashlib
import logging
import urllib.parse

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils.crypto import get_random_string
from knox.models import AuthToken
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from django.shortcuts import redirect

from api.views.auth import _set_auth_cookies

try:
    import jwt
    from jwt import PyJWKClient
    _PYJWT_AVAILABLE = True
except ImportError:
    _PYJWT_AVAILABLE = False

logger = logging.getLogger(__name__)
User = get_user_model()

_DISCOVERY_CACHE_KEY = "oidc:discovery"
_DISCOVERY_CACHE_TTL = 3600  # 1 hour — re-fetch if provider rotates keys


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

def _oidc_enabled() -> bool:
    """Return True only when all three required settings are non-empty."""
    return bool(
        getattr(settings, "OIDC_SERVER_URL", "")
        and getattr(settings, "OIDC_CLIENT_ID", "")
        and getattr(settings, "OIDC_CLIENT_SECRET", "")
    )


def _frontend_error(code: str) -> str:
    """Build a redirect URL that LoginPage.tsx will interpret as an SSO error."""
    return _frontend_url(f"/login?sso_error={urllib.parse.quote(code)}")


def _frontend_url(path: str = "/") -> str:
    trusted = getattr(settings, "CSRF_TRUSTED_ORIGINS", [])
    base = trusted[0].rstrip("/") if trusted else ""
    return f"{base}{path}"


# ---------------------------------------------------------------------------
# OIDC Discovery
# ---------------------------------------------------------------------------

def _get_discovery() -> dict:
    """
    Fetch and cache the provider's OpenID Connect discovery document.
    Cached for _DISCOVERY_CACHE_TTL seconds so we don't hit the IdP on
    every login request.
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
    except requests.RequestException as exc:
        logger.error("OIDC discovery fetch failed: %s", exc, exc_info=True)
        raise

    cache.set(_DISCOVERY_CACHE_KEY, doc, _DISCOVERY_CACHE_TTL)
    return doc


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def _generate_pkce_pair() -> dict:
    """
    Generate a PKCE S256 code_verifier / code_challenge pair.
    The verifier is a 64-char random string; the challenge is its
    SHA-256 hash encoded as URL-safe base64 without padding.
    """
    code_verifier = get_random_string(64)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")
    return {"code_verifier": code_verifier, "code_challenge": code_challenge}


# ---------------------------------------------------------------------------
# Redirect URI
# ---------------------------------------------------------------------------

def _redirect_uri(request) -> str:
    override = getattr(settings, "OIDC_REDIRECT_URI", None)
    if override:
        return override
    # Auto-derive from the request so it works behind any hostname.
    # SECURE_PROXY_SSL_HEADER and USE_X_FORWARDED_HOST must be set
    # in settings.py for this to produce an https:// URL behind Traefik.
    return request.build_absolute_uri("/api/oidc/callback/")


# ---------------------------------------------------------------------------
# GET /api/oidc/login/
# ---------------------------------------------------------------------------

class OIDCLoginView(APIView):
    """
    Step 1 of the OIDC flow.

    Generates state (CSRF token), nonce (replay protection), and a PKCE
    S256 pair. Stores all three in the session, then redirects the browser
    to the provider's authorization_endpoint.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        if not _oidc_enabled():
            logger.warning("OIDC login attempted but SSO is not configured.")
            return redirect(_frontend_error("provider_unavailable"))

        try:
            discovery = _get_discovery()
        except Exception:
            return redirect(_frontend_error("provider_unavailable"))

        state = get_random_string(32)
        nonce = get_random_string(32)
        pkce  = _generate_pkce_pair()

        # Bind all three to the session — callback verifies each one.
        request.session["oidc_state"]         = state
        request.session["oidc_nonce"]         = nonce
        request.session["oidc_code_verifier"] = pkce["code_verifier"]
        request.session.save()

        scopes = getattr(settings, "OIDC_SCOPES", "openid email profile")

        params = {
            "response_type":         "code",
            "client_id":             settings.OIDC_CLIENT_ID,
            "redirect_uri":          _redirect_uri(request),
            "scope":                 scopes,
            "state":                 state,
            "nonce":                 nonce,
            # PKCE — prevents authorization code interception attacks
            "code_challenge":        pkce["code_challenge"],
            "code_challenge_method": "S256",
        }

        auth_url = (
            f"{discovery['authorization_endpoint']}?"
            f"{urllib.parse.urlencode(params)}"
        )
        return redirect(auth_url)


# ---------------------------------------------------------------------------
# GET /api/oidc/callback/
# ---------------------------------------------------------------------------

class OIDCCallbackView(APIView):
    """
    Step 2 of the OIDC flow.

    Validates state → exchanges code (with PKCE verifier) → validates
    id_token signature via JWKS → verifies nonce → gets-or-creates user
    → issues Knox token → redirects React SPA with token in URL fragment.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        # ── Provider-side error ──────────────────────────────────────────
        if "error" in request.GET:
            error = request.GET.get("error", "unknown")
            logger.warning("OIDC provider returned error: %s", error)
            return redirect(_frontend_error(error))

        code  = request.GET.get("code")
        state = request.GET.get("state")

        if not code or not state:
            return redirect(_frontend_error("missing_params"))

        # ── State verification (CSRF protection) ─────────────────────────
        session_state    = request.session.pop("oidc_state",         None)
        session_nonce    = request.session.pop("oidc_nonce",         None)
        code_verifier    = request.session.pop("oidc_code_verifier", None)

        if not session_state or state != session_state:
            logger.warning("OIDC state mismatch — possible CSRF attack")
            return redirect(_frontend_error("state_mismatch"))

        if not code_verifier:
            # Session expired between login and callback
            logger.warning("OIDC code_verifier missing from session")
            return redirect(_frontend_error("state_mismatch"))

        # ── Discovery ────────────────────────────────────────────────────
        try:
            discovery = _get_discovery()
        except Exception:
            return redirect(_frontend_error("provider_unavailable"))

        # ── Token exchange ───────────────────────────────────────────────
        #
        # Send code_verifier (PKCE) so the provider can verify it matches
        # the challenge sent in step 1.
        # Use HTTP Basic auth (client_id:client_secret) rather than putting
        # the secret in the request body — more spec-compliant and avoids
        # the secret appearing in server-side request logs.
        try:
            token_resp = requests.post(
                discovery["token_endpoint"],
                data={
                    "grant_type":    "authorization_code",
                    "code":          code,
                    "redirect_uri":  _redirect_uri(request),
                    "client_id":     settings.OIDC_CLIENT_ID,
                    "code_verifier": code_verifier,
                },
                auth=(settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET),
                timeout=10,
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except requests.RequestException as exc:
            logger.error("OIDC token exchange failed: %s", exc, exc_info=True)
            return redirect(_frontend_error("token_exchange_failed"))

        id_token_raw = token_data.get("id_token")
        access_token = token_data.get("access_token")

        if not id_token_raw:
            logger.error("OIDC token response missing id_token")
            return redirect(_frontend_error("token_exchange_failed"))

        # ── ID token validation ───────────────────────────────────────────
        #
        # Full signature verification via the provider's JWKS endpoint.
        # PyJWT fetches and caches the signing keys automatically.
        # Falls back to basic base64 decode if PyJWT is not installed —
        # install PyJWT[cryptography] in production.
        claims = _validate_id_token(id_token_raw, discovery, session_nonce)
        if claims is None:
            return redirect(_frontend_error("token_validation_failed"))

        # ── Userinfo (optional — claims may already have what we need) ────
        #
        # Fetch userinfo if email was not in the id_token claims directly.
        # Most providers include email in the id_token when the openid +
        # email scopes are requested, making this roundtrip unnecessary.
        email = claims.get("email")
        if not email and access_token:
            try:
                userinfo_resp = requests.get(
                    discovery["userinfo_endpoint"],
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10,
                )
                userinfo_resp.raise_for_status()
                userinfo = userinfo_resp.json()
                # Merge — id_token claims take precedence
                email = userinfo.get("email", "")
                claims.setdefault("given_name",  userinfo.get("given_name",  ""))
                claims.setdefault("family_name", userinfo.get("family_name", ""))
                claims.setdefault("preferred_username", userinfo.get("preferred_username", ""))
            except requests.RequestException as exc:
                logger.error("OIDC userinfo fetch failed: %s", exc, exc_info=True)
                return redirect(_frontend_error("userinfo_failed"))

        if not email:
            logger.error("OIDC: no email claim in id_token or userinfo")
            return redirect(_frontend_error("userinfo_failed"))

        # ── Get-or-create user ───────────────────────────────────────────
        try:
            user = _get_or_create_user(claims, email)
        except Exception as exc:
            logger.error("OIDC user resolution failed: %s", exc, exc_info=True)
            return redirect(_frontend_error("user_resolution_failed"))

        if not user.is_active:
            return redirect(_frontend_error("account_disabled"))

        # ── Issue Knox token ─────────────────────────────────────────────
        token_instance, knox_token = AuthToken.objects.create(user=user)
        (
            token_instance.expiry.isoformat() if token_instance.expiry else ""
        )

        logger.info(
            "OIDC login successful: user=%s email=%s",
            user.username, email,
        )

        # Set the Knox token as an httpOnly cookie and redirect the browser
        # to the SPA login page with ?sso=1 to trigger color hydration.
        # The token never appears in URLs or server logs.
        ttl = settings.REST_KNOX.get("TOKEN_TTL")
        max_age = int(ttl.total_seconds()) if ttl else 36_000

        response = redirect(_frontend_url("/login?sso=1"))
        _set_auth_cookies(response, knox_token, max_age, secure=not settings.DEBUG)
        return response


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------

def _validate_id_token(
    id_token_raw: str,
    discovery: dict,
    session_nonce: str | None,
) -> dict | None:
    """
    Validate the id_token and return its claims, or None on failure.

    With PyJWT[cryptography] installed (recommended):
      • Fetches the provider's JWKS
      • Verifies the signature algorithm matches the provider's advertised list
      • Validates aud (must match OIDC_CLIENT_ID), iss, exp, nbf
      • Verifies the nonce claim

    Without PyJWT (fallback — not recommended for production):
      • Base64-decodes the payload without signature verification
      • Only verifies the nonce claim
    """
    if _PYJWT_AVAILABLE:
        return _validate_id_token_pyjwt(id_token_raw, discovery, session_nonce)
    else:
        logger.warning(
            "PyJWT not installed — falling back to unverified id_token decode. "
            "Install PyJWT[cryptography] for production use."
        )
        return _validate_id_token_fallback(id_token_raw, session_nonce)


def _validate_id_token_pyjwt(
    id_token_raw: str,
    discovery: dict,
    session_nonce: str | None,
) -> dict | None:
    """Full validation using PyJWT + JWKS."""
    try:
        jwks_client = PyJWKClient(discovery["jwks_uri"])
        signing_key = jwks_client.get_signing_key_from_jwt(id_token_raw)

        algorithms = discovery.get(
            "id_token_signing_alg_values_supported", ["RS256"]
        )

        claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=algorithms,
            audience=settings.OIDC_CLIENT_ID,
            issuer=discovery["issuer"],
            # leeway tolerates up to 10s clock skew between IdP and server
            leeway=10,
        )
    except Exception as exc:
        logger.error("OIDC id_token validation failed: %s", exc, exc_info=True)
        return None

    # Nonce — replay protection
    if session_nonce and claims.get("nonce") != session_nonce:
        logger.warning("OIDC nonce mismatch")
        return None

    return claims


def _validate_id_token_fallback(
    id_token_raw: str,
    session_nonce: str | None,
) -> dict | None:
    """
    Fallback: decode payload without signature verification.
    Only verifies the nonce. Use only in development or when the IdP
    does not expose a JWKS endpoint.
    """
    try:
        payload_part = id_token_raw.split(".")[1]
        padded = payload_part + "=" * (-len(payload_part) % 4)
        import base64 as _base64
        import json as _json
        claims = _json.loads(_base64.urlsafe_b64decode(padded))
    except Exception as exc:
        logger.error("OIDC id_token decode failed: %s", exc, exc_info=True)
        return None

    if session_nonce and claims.get("nonce") != session_nonce:
        logger.warning("OIDC nonce mismatch (fallback validator)")
        return None

    return claims


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def _get_or_create_user(claims: dict, email: str) -> "User":
    """
    Map OIDC claims to a local Django user.

    Lookup strategy:
      1. By email — most stable cross-provider identifier.
      2. Fall back to preferred_username or sub if email is absent
         (shouldn't happen after the email guard in the callback, but
         defensive programming is warranted here).

    Name fields are updated on every login so they stay in sync with the
    directory (e.g. after a legal name change).
    """
    email = email.lower().strip()

    username = (
        claims.get("preferred_username")
        or claims.get("sub")
        or email.split("@")[0]
        or "oidc_user"
    )[:150]

    first_name = (
        claims.get("given_name")
        or (claims.get("name", "").split() or [""])[0]
    )[:150]

    last_name  = (claims.get("family_name") or "")[:150]

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username":   username,
            "first_name": first_name,
            "last_name":  last_name,
        },
    )

    if not created:
        # Sync name fields — only write if something actually changed
        update_fields = []
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            update_fields.append("first_name")
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            update_fields.append("last_name")
        if update_fields:
            user.save(update_fields=update_fields)

    logger.info(
        "OIDC user resolved: username=%s email=%s created=%s",
        user.username, email, created,
    )
    return user