"""PrefixSink — write a local submission dir to S3 as the portable prefix
contract (one bucket, prefix-per-submission, _status.json last)."""
import json
import logging
import pathlib

import classes.models.submission_contract as sc
import classes.models.email_contract as _ec
ec_email_metadata_name = _ec.EMAIL_METADATA_OBJECT_NAME

logger = logging.getLogger("email-feeder.minio")


class PrefixSink:
    def __init__(self, minio_service, bucket_name: str):
        self._svc = minio_service
        self._bucket = bucket_name

    def store(self, submission_dir: pathlib.Path, submission_id: str,
              reported_by: str) -> None:
        self._svc.ensure_bucket(self._bucket)

        emails: list[str] = []
        attachments: list[str] = []
        files = [p for p in submission_dir.rglob("*") if p.is_file()]

        for fpath in files:
            rel = fpath.relative_to(submission_dir).as_posix()
            object_name = f"{submission_id}/{rel}"
            self._svc.upload_file(
                bucket_name=self._bucket, file_path=fpath, object_name=object_name,
            )
            if rel == sc.STATUS_OBJECT_NAME:
                continue
            if rel.endswith(sc.SUBMISSION_EML_SUFFIX):
                continue  # wrapper is not an email-to-analyze
            if pathlib.PurePosixPath(rel).name == ec_email_metadata_name:  # email.json
                continue
            if rel.lower().endswith(".eml"):
                emails.append(object_name)
            else:
                attachments.append(object_name)

        manifest = sc.build_status(
            submission_id=submission_id, reported_by=reported_by,
            emails_to_analyze=emails, attachments=attachments,
        )
        raw = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        # _status.json LAST — readers skip prefixes without it.
        self._svc.upload_bytes(
            bucket_name=self._bucket,
            object_name=f"{submission_id}/{sc.STATUS_OBJECT_NAME}",
            data=raw, content_type="application/json",
        )
        logger.info("Stored submission %s (%d email(s), %d attachment(s))",
                    submission_id, len(emails), len(attachments))
