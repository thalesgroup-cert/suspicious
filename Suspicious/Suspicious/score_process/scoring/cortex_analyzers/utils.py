"""
Shared utility functions for the Cortex analyzer layer.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from domain_process.domain_utils.domain_handler import DomainHandler

_domain_handler = DomainHandler()


def extract_domain(value: str) -> Optional[str]:
    """
    Return the bare hostname for a URL or plain domain string.

    Uses urlparse().hostname (not .netloc) to strip any port number.
    Returns None when the value is neither a recognised domain nor a URL.
    """
    domain_type = _domain_handler.validate_domain(value)
    if domain_type == "Domain":
        return value
    if domain_type == "Url":
        return urlparse(value).hostname or None
    return None


def dump_model(model: Any) -> dict:
    """
    Serialise a Pydantic model (v1 or v2) or plain dict to a dict.

    Pydantic v2: model_dump(exclude_none=True)
    Plain dict:  returned as-is
    Other:       attempt model_dump(), then dict(), then raise TypeError
    """
    if isinstance(model, dict):
        return model
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=True)
    if hasattr(model, "dict"):
        return model.dict(exclude_none=True)
    raise TypeError("Cannot serialise %r to dict." % type(model))