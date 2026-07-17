from knox.auth import TokenAuthentication

KNOX_COOKIE_NAME = "knox_token"

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
        return self.authenticate_credentials(token.encode("utf-8"))
