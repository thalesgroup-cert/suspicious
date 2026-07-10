"""Build the canonical EmailDataModel from a feeder EmailMetadata (fast path).

Mirrors parse_email's post-extraction massaging so the fast path and the
parse_email fallback produce identical models. Attachment bytes are hydrated
from disk and integrity-checked against the contract sha256."""
import hashlib
import os

from mail_feeder import email_contract as ec
from .models import EmailDataModel, AttachmentModel


class MetadataIntegrityError(Exception):
    """An attachment file is missing or its sha256 does not match the contract."""


def build_email_data_model(
    meta: ec.EmailMetadata, reported_by: str, attachments_dir: str
) -> EmailDataModel:
    attachments = []
    for att in meta.attachments:
        path = os.path.join(attachments_dir, os.path.basename(att.filename))
        if not os.path.isfile(path):
            raise MetadataIntegrityError(f"missing attachment file: {att.filename}")
        with open(path, "rb") as f:
            content = f.read()
        digest = hashlib.sha256(content).hexdigest()
        if digest != att.sha256:
            raise MetadataIntegrityError(
                f"sha256 mismatch for {att.filename}: {digest} != {att.sha256}")
        attachments.append(AttachmentModel(
            filename=att.filename, content=content,
            headers=att.headers, parent=meta.id,
        ))

    to_addr, reporter = ec.resolve_reporter_and_to(meta.to, reported_by)

    return EmailDataModel(
        reportedBy=reporter,
        **{
            "from": meta.from_,
            "to": to_addr,
            "cc": meta.cc,
            "bcc": meta.bcc,
            "reportedSubject": meta.reportedSubject,
            "reportedText": meta.reportedText,
            "date": meta.date,
            "headers": meta.headers,
            "id": meta.id,
            "attachments": attachments,
        },
    )
