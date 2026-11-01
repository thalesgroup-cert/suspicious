"""The label ledger writers (Plan D). Append-only: a row is never updated except its status,
flag_reason and resolution fields (rulings D4, D5)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timezone

from ai_model.messageid import match_case, message_id_hash, stored_sender
from ai_model.models import AiAssessment, LabelRecord
from ai_model.taxonomy import class_of


@dataclass(frozen=True)
class FolderObservation:
    """A ReviewMail with its key, class, matched case and snapshot, computed before the write."""
    mail: object
    message_id: str
    message_hash: str
    label_class: str
    case: object
    snapshot: dict


def _folder_key(mail) -> tuple[str, str]:
    """(message_id, message_id_hash). With no Message-ID the hash is derived from the content
    (sender, UTC date, subject, text), so a UIDVALIDITY reset or a move to another folder still
    finds the same message."""
    if mail.message_id:
        return mail.message_id, message_id_hash(mail.message_id)
    date = mail.date.astimezone(timezone.utc).isoformat() if mail.date else ""
    text_hash = hashlib.sha256(mail.text.encode("utf-8", "surrogatepass")).hexdigest()
    return "", message_id_hash(f"no-message-id:{mail.sender}|{date}|{mail.subject.lower()}|{text_hash}")


def _folder_rows(message_hash: str):
    return LabelRecord.objects.filter(message_id_hash=message_hash, source=LabelRecord.Source.IMAP_FOLDER)


def _observed(message_hash: str, folder: str) -> bool:
    """A row for this message and folder that is active or flagged. A superseded one does not
    count: the mail moved away and back, so the folder is its label again."""
    return _folder_rows(message_hash).filter(label=folder).exclude(status=LabelRecord.Status.SUPERSEDED).exists()


def is_observed(mail) -> bool:
    return _observed(_folder_key(mail)[1], mail.folder)


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
    sender = (stored_sender(stored) if stored is not None else "") or mail.sender
    ai = AiAssessment.objects.filter(case=case).values("result", "model_version").first() if case else None
    return {
        "sender_domain": sender.rpartition("@")[2].lower(),
        "subject_length": len(mail.subject),
        "is_allowlisted": case.is_allowlisted if case else None,
        "is_denylisted": case.is_denylisted if case else None,
        "ai_result": ai["result"] if ai else None,
        "ai_model_version": ai["model_version"] if ai else None,
    }


def prepare_folder_observation(mail) -> FolderObservation | None:
    """The read-only pre-pass for a ReviewMail: None when the folder has no known class or the
    message is already observed there, else its key, matched case and snapshot."""
    label_class = class_of(mail.folder)
    message_id, message_hash = _folder_key(mail)
    if label_class is None or _observed(message_hash, mail.folder):
        return None
    case = _match(mail)
    return FolderObservation(mail, message_id, message_hash, label_class, case, _snapshot(mail, case))


def record_folder_observation(observation: FolderObservation, vectors, *, preprocessing_version,
                              embedding_version) -> LabelRecord | None:
    """Append the folder row; None when a concurrent write got there first (re-checked here).

    `vectors` is {"classifier": [float, ...], "campaign": [float, ...]}. The new row supersedes
    the message's active rows in other folders (ruling D5). Run it in a transaction.
    """
    mail = observation.mail
    if _observed(observation.message_hash, mail.folder):
        return None
    _folder_rows(observation.message_hash).filter(status=LabelRecord.Status.ACTIVE).update(
        status=LabelRecord.Status.SUPERSEDED
    )
    return LabelRecord.objects.create(
        message_id=observation.message_id,
        message_id_hash=observation.message_hash,
        case=observation.case,
        source=LabelRecord.Source.IMAP_FOLDER,
        source_ref=f"{mail.folder}:{mail.uidvalidity}:{mail.uid}",
        label=mail.folder,
        label_class=observation.label_class,
        trust=LabelRecord.Trust.FOLDER,
        embedding=json.dumps(vectors["classifier"]),
        preprocessing_version=preprocessing_version,
        campaign_embedding=json.dumps(vectors["campaign"]),
        embedding_version=embedding_version,
        snapshot=observation.snapshot,
    )
