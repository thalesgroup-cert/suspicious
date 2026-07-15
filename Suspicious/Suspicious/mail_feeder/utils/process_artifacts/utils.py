import base64
import logging
from urllib.parse import urlparse, urlunparse, parse_qs
from typing import Optional, Tuple
from pydantic import ValidationError
from .models import URLDecodeResult

logger = logging.getLogger(__name__)


def get_prime_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query='', fragment=''))


def decode_base64_from_tid_param(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        tid = parse_qs(parsed.query).get('tid', [None])[0]
        if tid:
            padded = tid + '=' * (-len(tid) % 4)
            return base64.urlsafe_b64decode(padded).decode('utf-8')
    except Exception as e:
        logger.error(f"Base64 decoding failed: {e}")
    return None


def _as_valid_url(candidate: Optional[str]) -> Optional[str]:
    """Returns candidate if it validates as an HttpUrl, else None."""
    if not candidate:
        return None
    try:
        URLDecodeResult(prime_url=candidate)
        return candidate
    except ValidationError as e:
        # The extractor occasionally emits malformed/merged URL strings (e.g. two
        # links joined by a space) that fail HttpUrl validation. Drop just that
        # field instead of failing the whole artifact.
        logger.error(f"Malformed URL '{candidate}': {e}")
        return None


def extract_url_info(url: str) -> URLDecodeResult:
    prime = _as_valid_url(get_prime_url(url))
    decoded = _as_valid_url(decode_base64_from_tid_param(url))
    return URLDecodeResult(prime_url=prime, decoded_url=decoded)
