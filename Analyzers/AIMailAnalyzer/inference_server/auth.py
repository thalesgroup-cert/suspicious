"""Bearer-token guard for the /v2 API.

The token is read from AI_INFERENCE_TOKEN on every request. An unset or empty
token fails closed (503) rather than leaving the routes open.
"""
import os
import secrets

from fastapi import Header, HTTPException


def require_token(authorization: str | None = Header(None)) -> None:
    expected = os.environ.get("AI_INFERENCE_TOKEN", "")
    if not expected:
        raise HTTPException(503, "token not configured")
    scheme, _, supplied = (authorization or "").partition(" ")
    # compare_digest on bytes: str input raises TypeError for non-ASCII.
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(401, "invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
