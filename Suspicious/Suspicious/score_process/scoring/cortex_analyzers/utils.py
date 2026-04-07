# analyzers_services/utils.py
"""
Shared utility functions for the Cortex analyzer layer.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

from domain_process.domain_utils.domain_handler import DomainHandler

# Module-level singleton — DomainHandler may load config or open DB
# connections; creating one per call is wasteful.
_domain_handler = DomainHandler()

# Matches Cortex version suffixes like _4_0, _1_4, _10_0 at end of string
_VERSION_SUFFIX_RE = re.compile(r"_\d+_\d+$")


def normalize_analyzer_name(name: str) -> str:
    """
    Convert a Cortex analyzer name to the lowercase key used in REGISTRY.

    Examples
    --------
    "MailHeader_4_0"       → "mailheader"
    "VirustotalQuery_2_0"  → "virustotalquery"
    "AI_Mail_Analyzer_1_4" → "ai"
    "Yara_Boosted_3_2"     → "yara"
    "MailHeader_10_0"      → "mailheader"   (two-digit version)
    """
    stripped = _VERSION_SUFFIX_RE.sub("", name)
    return stripped.split("_")[0].lower()


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
    # Pydantic v1 fallback — kept for transitional codebases
    if hasattr(model, "dict"):
        return model.dict(exclude_none=True)
    raise TypeError("Cannot serialise %r to dict." % type(model))