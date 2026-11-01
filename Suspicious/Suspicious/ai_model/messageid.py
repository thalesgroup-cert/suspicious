"""Message-ID normalisation and the match of a mail to a stored case (Plan D, ruling D3)."""
from __future__ import annotations

import hashlib
from datetime import datetime, time, timedelta, timezone as dt_timezone
from email.utils import parseaddr

from case_handler.models import Case
from connectors.contrib.thehive.utils import parse_and_decode_defaultdict
from mail_feeder.models import Mail


def normalise(header: str) -> str:
    """Strip whitespace and angle brackets, lower-case. "" for empty, a value with no "@", or one
    above 998 characters (the LabelRecord.message_id width and RFC 5322's line limit)."""
    value = (header or "").strip().strip("<>").strip().lower()
    local, _, domain = value.partition("@")
    return value if local and domain and len(value) <= 998 and not any(c.isspace() for c in value) else ""


def message_id_hash(normalised: str) -> str:
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _headers(mail) -> dict[str, list[str]]:
    try:
        return parse_and_decode_defaultdict(mail.mail_header.header_value) if mail.mail_header_id else {}
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return {}


def _values(headers: dict[str, list[str]], name: str) -> list[str]:
    return [v for k, vs in headers.items() if k.lower() == name for v in vs]


def _address(value: str) -> str:
    return parseaddr(value or "")[1].strip().lower()


def stored_sender(mail) -> str:
    """The stored mail's sender address, lower-cased: mail_from, else the stored From header."""
    return _address(mail.mail_from) or next((_address(v) for v in _values(_headers(mail), "from")), "")


def _cases_of(mails):
    """One case per mail, newest first, each case once."""
    return list({c.pk: c for c in Case.objects.filter(fileOrMail__mail__in=mails).order_by("-pk")}.values())


def match_case(message_id: str, *, sender: str = "", date=None, subject: str = ""):
    """The case whose stored mail carries this Message-ID, else (no Message-ID) the one case with the
    same sender, UTC day and subject. None when nothing matches or the fallback is ambiguous."""
    wanted = normalise(message_id)
    if wanted:
        # ponytail: LIKE scan of MailHeader.header_value (unindexed), then confirm by parsing; store the
        # Message-ID hash on Mail to make it an indexed lookup. Ids with characters the repr escapes
        # (backslash, mixed quotes) may be missed by the prefilter.
        mails = Mail.objects.filter(mail_header__header_value__icontains=wanted).select_related("mail_header")
        hits = [m for m in mails if wanted in {normalise(v) for v in _values(_headers(m), "message-id")}]
        return next(iter(_cases_of(hits)), None) if hits else None
    if not (date and subject and sender):
        return None
    day = date.astimezone(dt_timezone.utc).date()
    start = datetime.combine(day, time.min, tzinfo=dt_timezone.utc)
    mails = Mail.objects.filter(date__gte=start, date__lt=start + timedelta(days=1), subject__iexact=subject.strip())
    want = _address(sender)
    hits = [
        m for m in mails.select_related("mail_header")
        if stored_sender(m) == want
    ]
    cases = _cases_of(hits)
    return cases[0] if len(cases) == 1 else None
