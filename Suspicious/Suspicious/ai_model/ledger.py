"""The label ledger writers (Plan D). Append-only: a row is never updated except its status,
flag_reason and resolution fields (rulings D4, D5)."""
from __future__ import annotations

import json

from ai_model.messageid import _address, _headers, _values, match_case, message_id_hash
from ai_model.models import AiAssessment, LabelRecord
from ai_model.taxonomy import class_of


def _folder_key(mail) -> tuple[str, str]:
    """(message_id, message_id_hash). With no Message-ID the hash is keyed on the folder position,
    so the same observation is still recognised."""
    if mail.message_id:
        return mail.message_id, message_id_hash(mail.message_id)
    return "", message_id_hash(f"no-message-id:{mail.folder}:{mail.uidvalidity}:{mail.uid}")


def _folder_rows(message_hash: str):
    return LabelRecord.objects.filter(message_id_hash=message_hash, source=LabelRecord.Source.IMAP_FOLDER)


def is_observed(mail) -> bool:
    """True when this message already has a row for this folder (any status)."""
    return _folder_rows(_folder_key(mail)[1]).filter(label=mail.folder).exists()


def _match(mail):
    """Outer Message-ID (or, with none, sender + day + subject), then each nested Message-ID."""
    case = match_case(mail.message_id, sender=mail.sender, date=mail.date, subject=mail.subject)
    for inner in mail.inner_message_ids:
        if case is not None:
            break
        case = match_case(inner)
    return case


def _snapshot(mail, case) -> dict:
    """Ruling D9: only what is cheap and already stored at observation time."""
    stored = getattr(getattr(case, "fileOrMail", None), "mail", None) if case else None
    sender = ""
    if stored is not None:
        sender = _address(stored.mail_from) or next((_address(v) for v in _values(_headers(stored), "from")), "")
    sender = sender or mail.sender
    ai = AiAssessment.objects.filter(case=case).values("result", "model_version").first() if case else None
    return {
        "sender_domain": sender.rpartition("@")[2].lower(),
        "subject_length": len(mail.subject),
        "is_allowlisted": case.is_allowlisted if case else None,
        "is_denylisted": case.is_denylisted if case else None,
        "ai_result": ai["result"] if ai else None,
        "ai_model_version": ai["model_version"] if ai else None,
    }


def record_folder_observation(mail, vectors, *, preprocessing_version, embedding_version):
    """Append the folder row for a ReviewMail; None when this message already has a row for this
    folder (idempotent on message hash + folder) or the folder has no known class.

    `vectors` is {"classifier": [float, ...], "campaign": [float, ...]}. A new row for another
    folder supersedes the message's active folder rows (ruling D5). Run it in a transaction.
    """
    label_class = class_of(mail.folder)
    if label_class is None or is_observed(mail):
        return None
    message_id, message_hash = _folder_key(mail)
    case = _match(mail)
    _folder_rows(message_hash).filter(status=LabelRecord.Status.ACTIVE).update(
        status=LabelRecord.Status.SUPERSEDED
    )
    return LabelRecord.objects.create(
        message_id=message_id,
        message_id_hash=message_hash,
        case=case,
        source=LabelRecord.Source.IMAP_FOLDER,
        source_ref=f"{mail.folder}:{mail.uidvalidity}:{mail.uid}",
        label=mail.folder,
        label_class=label_class,
        trust=LabelRecord.Trust.FOLDER,
        embedding=json.dumps(vectors["classifier"]),
        preprocessing_version=preprocessing_version,
        campaign_embedding=json.dumps(vectors["campaign"]),
        embedding_version=embedding_version,
        snapshot=_snapshot(mail, case),
    )
