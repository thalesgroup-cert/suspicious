"""When an allow-list may overrule the AI's verdict on a mail.

The AI reads the mail text, which is not an allow-listable artifact, so by default no allow-list
overrules it (otherwise one allow-listed link in a phishing mail would hide the AI's finding).
A legitimate company mail the AI got wrong can be let through when the mail provably comes from
the company and links only to things we already trust:

- the From domain is a company domain,
- an Authentication-Results header stamped by one of *our* gateways (``scoring.trusted_authserv_ids``)
  says dmarc=pass for that domain, and
- every artifact in the mail is allow-listed or on a company domain.

An empty ``scoring.trusted_authserv_ids`` (the default) switches this off.
"""
from __future__ import annotations

import email
import email.policy
import logging
import re

from settings.config import get_config

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_DMARC_PASS = re.compile(r"^dmarc\s*=\s*pass\b", re.IGNORECASE)
_HEADER_FROM = re.compile(r"\bheader\.from\s*=\s*([^\s;()]+)", re.IGNORECASE)


def _from_domain(msg) -> str:
    """The domain of the single From address; "" when there is not exactly one."""
    values = msg.get_all("From", [])
    if len(values) != 1:
        return ""
    try:
        addresses = values[0].addresses
    except AttributeError:
        return ""
    if len(addresses) != 1:
        return ""
    return (addresses[0].domain or "").strip().lower().rstrip(".")


def authenticated_company_sender(raw_headers: str, trusted_ids, company_domains) -> bool:
    """True when the mail's only From is a company domain and a trusted gateway reports dmarc=pass for it.

    Only Authentication-Results headers whose authserv-id is in ``trusted_ids`` count: anything
    else in a forwarded mail can be written by the sender.
    """
    from connectors.contrib.misp.internal import is_company_domain

    trusted = {str(t).strip().lower() for t in (trusted_ids or []) if str(t).strip()}
    if not trusted or not raw_headers:
        return False
    msg = email.message_from_string(raw_headers, policy=email.policy.default)
    domain = _from_domain(msg)
    if not domain or not is_company_domain(domain, company_domains):
        return False
    for value in msg.get_all("Authentication-Results", []):
        parts = [p.strip() for p in str(value).split(";")]
        authserv = parts[0].split()[0].lower() if parts and parts[0].split() else ""
        if authserv not in trusted:
            continue
        for method in parts[1:]:
            if not _DMARC_PASS.match(method):
                continue
            aligned = _HEADER_FROM.search(method)
            if aligned is None or aligned.group(1).strip().lower().rstrip(".") == domain:
                return True
    return False


def _listed(kind: str, value: str, company_domains) -> bool:
    from connectors.contrib.misp.internal import is_company_domain, url_host
    from score_process.scoring.cortex_analyzers.allow_list import check_allow_list

    if kind == "url":
        return is_company_domain(url_host(value), company_domains) or any(check_allow_list(value, "url").model_dump().values())
    if kind == "domain":
        return is_company_domain(value, company_domains) or any(check_allow_list(value, "domain").model_dump().values())
    if kind == "ip":
        return any(check_allow_list(value, "ip").model_dump().values())
    if kind == "address":
        domain = value.rsplit("@", 1)[-1]
        return is_company_domain(domain, company_domains) or any(check_allow_list(domain, "domain").model_dump().values())
    return False


def all_artifacts_listed(mail, company_domains) -> bool:
    """Every URL, domain, IP and address in the mail is allow-listed or on a company domain.

    A hash (an attachment) is never "listed" here: a company mail with attachments is left to the analysts.
    """
    for artifact in mail.mail_artifacts.all():
        for attr, field, kind in (("artifactIsUrl", "url", "url"), ("artifactIsDomain", "domain", "domain"),
                                  ("artifactIsIp", "ip", "ip"), ("artifactIsMailAddress", "mail_address", "address")):
            link = getattr(artifact, attr, None)
            if not link:
                continue
            target = getattr(link, field, None)
            value = getattr(target, "address", None) or getattr(target, "value", None) or ""
            if not _listed(kind, value, company_domains):
                return False
        if getattr(artifact, "artifactIsHash", None):
            return False
    return True


def read_mail_headers(store, mail_id: str) -> str:
    from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import _find_mail_bucket, _read_object_safe

    bucket = _find_mail_bucket(store, mail_id)
    if not bucket:
        return ""
    prefix = f"{mail_id}/"
    for obj in store.list(bucket, prefix=prefix, recursive=True):
        if obj.name.endswith(".headers"):
            return _read_object_safe(store, bucket, obj.name).decode("utf-8", "replace")
    return ""


def ai_may_be_overruled(case) -> bool:
    """Fails closed: any doubt, error or missing input means the AI is not overruled."""
    trusted = get_config("scoring.trusted_authserv_ids")
    if not trusted or not isinstance(trusted, (list, tuple)):
        return False
    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
    if mail is None:
        return False
    try:
        from common.storage import get_store
        from connectors.contrib.misp.internal import company_domains

        domains = company_domains()
        headers = read_mail_headers(get_store(), str(mail.mail_id))
        return authenticated_company_sender(headers, trusted, domains) and all_artifacts_listed(mail, domains)
    except Exception:  # noqa: BLE001 — a security relaxation must never depend on a lucky read
        logger.exception("trusted-sender check failed for case %s; not overruling the AI", getattr(case, "id", "?"))
        return False
