"""The label ledger writers (Plan D). Append-only: a row is never updated except its status,
flag_reason and resolution fields (rulings D4, D5)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timezone

from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone as dj_timezone

from ai_model.messageid import match_case, message_id_hash, stored_message_id, stored_sender
from ai_model.models import AiAssessment, LabelRecord
from ai_model.taxonomy import class_of
from case_handler.models import ProposedVerdict

ACTIVE, SUPERSEDED, FLAGGED = LabelRecord.Status.ACTIVE, LabelRecord.Status.SUPERSEDED, LabelRecord.Status.FLAGGED
MISMATCH = "folder_verdict_mismatch"
# Hard conflicts only: {folder class: the verdict class it conflicts with}. Unwanted, Suspicious and
# Inconclusive never flag.
CONFLICT = {"Dangerous": "Safe", "Safe": "Dangerous"}


def enabled() -> bool:
    """Ruling D6: verdict and challenge rows only while the ai_model connector is enabled."""
    from connectors.delivery import get_state
    from connectors.registry import registry
    return "ai_model" in registry.names() and get_state("ai_model").enabled


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
    every other non-superseded row of the message (active or flagged, all in other folders since
    this one has none; ruling D5): a move is the analysts' newer label, so a flag on the old folder
    row is moot and the new row is conflict-checked again. It is written flagged when it is a hard
    conflict with the active verdict. Runs in a transaction (savepoint inside the sync's chunk).
    """
    mail = observation.mail
    with transaction.atomic():
        if _observed(observation.message_hash, mail.folder):
            return None
        _folder_rows(observation.message_hash).exclude(status=SUPERSEDED).update(status=SUPERSEDED)
        conflict = CONFLICT.get(observation.label_class)
        locked = _conflicting_verdicts(observation.case, observation.message_hash, conflict) if conflict else []
        flagged = bool(list(locked))
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
            status=FLAGGED if flagged else ACTIVE,
            flag_reason=MISMATCH if flagged else "",
        )


def _stored_mail(case):
    return getattr(getattr(case, "fileOrMail", None), "mail", None)


def _case_key(case) -> tuple[str, str]:
    """(message_id, message_id_hash) of the case's stored mail. With no mail or no Message-ID the
    key is per case: the content key of folder rows needs the forwarded mail's text, which the
    verdict path does not read; folder rows still join on the case."""
    mail = _stored_mail(case)
    message_id = stored_message_id(mail) if mail is not None else ""
    if message_id:
        return message_id, message_id_hash(message_id)
    return "", message_id_hash(f"no-message-id:case:{case.pk}")


def _verdicts_for(case, message_hash: str):
    """Active verdict rows a folder row of this case (or, unmatched, this message) is checked against."""
    rows = LabelRecord.objects.filter(source=LabelRecord.Source.ANALYST_VERDICT, status=ACTIVE)
    return rows.filter(case=case) if case is not None else rows.filter(message_id_hash=message_hash)


def _conflicting_verdicts(case, message_hash: str, verdict_class: str):
    """The active verdict rows of that class, read with a row lock inside the caller's transaction so
    a verdict change cannot commit between this check and the folder row's insert.
    ponytail: locks existing rows only; a verdict row inserted by a transaction still open at that
    moment can be missed (next-key locking depends on the index the read uses), leaving that pair
    unflagged. A periodic re-check over active pairs closes it if it is ever seen."""
    return _verdicts_for(case, message_hash).filter(label_class=verdict_class).select_for_update()


def _folders_for(case, message_hash: str):
    """Active folder rows a verdict on this case is checked against: the case's rows, and rows of the
    same message that matched no case. A row of another case is not this verdict's mail."""
    return LabelRecord.objects.filter(source=LabelRecord.Source.IMAP_FOLDER, status=ACTIVE).filter(
        Q(case=case) | Q(case__isnull=True, message_id_hash=message_hash))


def record_verdict(case, user, label_class) -> LabelRecord | None:
    """Append the analyst's verdict; None for a result outside the label classes or the same class
    as the case's active verdict row. A different class supersedes that row; a hard conflict flags
    the folder rows (ruling D6)."""
    if label_class not in LabelRecord.LabelClass.values:
        return None
    # ponytail: no lock on the case; two verdicts on one case at the same instant can both append.
    with transaction.atomic():
        current = LabelRecord.objects.filter(case=case, source=LabelRecord.Source.ANALYST_VERDICT, status=ACTIVE)
        if current.filter(label_class=label_class).exists():
            return None
        current.update(status=SUPERSEDED)
        message_id, message_hash = _case_key(case)
        row = LabelRecord.objects.create(
            message_id=message_id, message_id_hash=message_hash, case=case,
            source=LabelRecord.Source.ANALYST_VERDICT, source_ref=user.get_username()[:255],
            label=label_class, label_class=label_class, trust=LabelRecord.Trust.VERDICT,
        )
        folder_classes = [f for f, v in CONFLICT.items() if v == label_class]
        _folders_for(case, message_hash).filter(label_class__in=folder_classes).update(
            status=FLAGGED, flag_reason=MISMATCH)
        return row


def record_challenge(case, proposed) -> LabelRecord | None:
    """Append the reporter's proposal (trust proposal, never trainable, never flags); None for a
    blank or unknown proposal."""
    if proposed not in ProposedVerdict.values:
        return None
    message_id, message_hash = _case_key(case)
    return LabelRecord.objects.create(
        message_id=message_id, message_id_hash=message_hash, case=case,
        source=LabelRecord.Source.CHALLENGE, label=proposed, label_class=proposed,
        trust=LabelRecord.Trust.PROPOSAL,
    )


def resolve_flag(record, user, note, *, keep: bool) -> None:
    """Close a flag: keep makes the row active again, else it is superseded. flag_reason stays as the
    audit trail (ruling D4). The row is re-read under a row lock, so a stale instance or a second
    resolver gets ValueError. With keep, any other active folder row of the message is superseded
    and carries the same resolution, naming this row."""
    with transaction.atomic():
        fresh = LabelRecord.objects.select_for_update().get(pk=record.pk)
        if fresh.status != FLAGGED:
            raise ValueError("only a flagged row can be resolved")
        now = dj_timezone.now()
        if keep and fresh.source == LabelRecord.Source.IMAP_FOLDER:
            _folder_rows(fresh.message_id_hash).filter(status=ACTIVE).exclude(pk=fresh.pk).update(
                status=SUPERSEDED, resolved_by=user, resolved_at=now,
                resolution_note=f"superseded by resolution of row {fresh.pk}")
        fresh.status = ACTIVE if keep else SUPERSEDED
        fresh.resolved_by, fresh.resolved_at, fresh.resolution_note = user, now, note
        fresh.save(update_fields=["status", "resolved_by", "resolved_at", "resolution_note"])
    record.status, record.resolved_by, record.resolved_at, record.resolution_note = (
        fresh.status, fresh.resolved_by, fresh.resolved_at, fresh.resolution_note)


def ledger_summary() -> dict:
    """Counts of the current rows (superseded ones are history) by source and class, the flagged
    count and the trainable count."""
    rows = LabelRecord.objects.exclude(status=SUPERSEDED).order_by()

    def by(field):
        return dict(rows.values_list(field).annotate(n=Count("id")))

    return {
        "by_source": by("source"),
        "by_class": by("label_class"),
        "flagged": rows.filter(status=FLAGGED).count(),
        "trainable": rows.filter(trust=LabelRecord.Trust.FOLDER, status=ACTIVE).count(),
    }
