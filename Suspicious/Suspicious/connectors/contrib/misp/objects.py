"""
MISP object builders.
"""
from __future__ import annotations
import logging
from typing import Optional

from pymisp import MISPObject

from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from score_process.scoring.header_parser import parse_email_headers

logger = logging.getLogger(__name__)

_SUPPORTED_HASH_TYPES = frozenset({"md5", "sha1", "sha256"})
_HASH_TYPE_MAP = {"sha-256": "sha256", "sha-1": "sha1", "md2": "md5"}


def build_email_object(mail, case_number, detection_level: str) -> Optional[MISPObject]:
    logger.debug("[MISPHandler] Building email object for case %s.", case_number)
    try:
        header_value  = getattr(getattr(mail, "mail_header", None), "header_value", None) or ""
        parsed        = parse_email_headers(header_value) if header_value else {}
        raw_subject   = getattr(mail, "subject", "") or ""
        clean_sub     = raw_subject.replace("\n", " ").replace("\r", "")

        obj         = MISPObject("email")
        obj.comment = "Case: %s, Detection level: %s" % (case_number, detection_level)

        obj.add_attribute("from",              value=parsed.get("from",              ""))
        obj.add_attribute("from-display-name", value=parsed.get("from_display_name", ""))
        obj.add_attribute("to",                value=parsed.get("to",                ""))
        obj.add_attribute("to-display-name",   value=parsed.get("to_display_name",   ""))
        obj.add_attribute("cc",                value=parsed.get("cc",                ""))
        obj.add_attribute("subject",           value=clean_sub)
        obj.add_attribute("reply-to",          value=parsed.get("reply_to",          ""))
        obj.add_attribute("return-path",       value=parsed.get("return_path",       ""))
        obj.add_attribute("user-agent",        value=parsed.get("user_agent",        ""))
        obj.add_attribute("send-date",         value=parsed.get("send_date",         ""))
        return obj

    except Exception as exc:
        logger.error("[MISPHandler] Error building email object for case %s: %s", case_number, exc, exc_info=True)
        return None


def build_url_object(url: URL, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject("url")
    obj.add_attribute("url",     type="url",     value=url.address)
    obj.add_attribute("comment", type="comment",
                      value="Artifact from case %s, IOC level: %s" % (case_number, detection_level),
                      distribution=0)
    return obj


def build_ip_object(ip: IP, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject("domain-ip")
    obj.add_attribute("ip",      type="ip-src",  value=ip.address)
    obj.add_attribute("comment", type="comment",
                      value="Artifact from case %s, IOC level: %s" % (case_number, detection_level),
                      distribution=0)
    return obj


def build_hash_object(
    hash_obj: Hash, case_number: str, detection_level: str
) -> Optional[MISPObject]:
    raw_type  = (hash_obj.type or "").lower()
    hash_type = _HASH_TYPE_MAP.get(raw_type, raw_type)
    if hash_type not in _SUPPORTED_HASH_TYPES:
        logger.warning(
            "[MISPHandler] Unsupported hash type %r for case %s — skipping.",
            hash_type, case_number,
        )
        return None   # explicit None, not bare return

    obj = MISPObject("file")
    obj.add_attribute(hash_type, type=hash_type, value=hash_obj.value)
    obj.add_attribute("comment", type="comment",
                      value="Artifact from case %s, IOC level: %s" % (case_number, detection_level),
                      distribution=0)
    return obj


def build_domain_object(domain: Domain, case_number: str, detection_level: str) -> MISPObject:
    obj = MISPObject("domain-ip")
    obj.add_attribute("domain",  type="domain",  value=domain.value)
    obj.add_attribute("comment", type="comment",
                      value="Artifact from case %s, IOC level: %s" % (case_number, detection_level),
                      distribution=0)
    return obj


def finalize_misp_object(
    misp_instance,
    event_id: str,
    misp_object: MISPObject,
) -> None:
    """Add misp_object to the event identified by event_id."""
    misp_instance.add_object(event_id, misp_object)