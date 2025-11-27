import base64
import logging
from urllib.parse import urlparse, urlunparse, parse_qs
from typing import Optional, Tuple
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


def extract_url_info(url: str) -> URLDecodeResult:
    prime = get_prime_url(url)
    decoded = decode_base64_from_tid_param(url)
    return URLDecodeResult(prime_url=prime, decoded_url=decoded)
