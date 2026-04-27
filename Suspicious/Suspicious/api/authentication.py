from knox.auth import TokenAuthentication

# Cookie name used for the httpOnly Knox session token.
# Must match the name used in LoginView, LogoutView, and OIDCCallbackView.
KNOX_COOKIE_NAME = "knox_token"

# Non-httpOnly indicator cookie.  JS can read this to know whether a session
# exists without making a network round-trip.  It carries no secret — the
# actual authentication is the httpOnly knox_token cookie.
SESSION_INDICATOR_COOKIE = "session_active"


class KnoxCookieAuthentication(TokenAuthentication):
    """
    Knox token authentication that reads the token from an httpOnly cookie
    instead of the Authorization header.

    This prevents XSS from stealing the token via localStorage, which is
    critical on a platform that processes attacker-controlled email content.

    Falls through (returns None) when the cookie is absent so that the
    standard Knox TokenAuthentication class (for API clients using the
    Authorization header) can still be tried next.
    """

    def authenticate(self, request):
        token = request.COOKIES.get(KNOX_COOKIE_NAME)
        if not token:
            return None
        # Knox's authenticate_credentials expects bytes (it calls .decode("utf-8")
        # internally because it normally receives the raw Authorization header value).
        return self.authenticate_credentials(token.encode("utf-8"))
