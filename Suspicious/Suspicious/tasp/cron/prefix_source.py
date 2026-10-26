"""Read the portable feeder contract: one bucket, prefix-per-submission.

Lists submission prefixes under a single feeder bucket and drives each
submission's status via its `_status.json` object: the portable replacement
for the legacy bucket-per-submission + bucket-tag scheme.
"""
from __future__ import annotations

import io
import json
import logging
import os
from typing import Iterator

from mail_feeder import submission_contract as sc

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class PrefixSource:
    def __init__(self, client, bucket_name: str):
        self._client = client
        self._bucket = bucket_name

    def _status_key(self, submission_id: str) -> str:
        return f"{submission_id}/{sc.STATUS_OBJECT_NAME}"

    def read_status(self, submission_id: str) -> dict:
        with self._client.open(self._bucket, self._status_key(submission_id)) as stream:
            return sc.parse_status(stream.read())

    def iter_pending(self) -> Iterator[str]:
        for name in self._client.list_prefixes(self._bucket):
            submission_id = name.rstrip("/")
            try:
                status = self.read_status(submission_id)
            except Exception:
                logger.warning("No/invalid _status.json for %s, skipping", submission_id)
                continue
            if status.get("status") in (sc.STATUS_TODO, sc.STATUS_PROCESSING):
                yield submission_id

    def _put_status(self, submission_id: str, manifest: dict) -> None:
        raw = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        self._client.put(
            self._bucket,
            self._status_key(submission_id),
            io.BytesIO(raw),
            length=len(raw),
            content_type="application/json",
        )

    def set_status(self, submission_id: str, status: str) -> None:
        manifest = self.read_status(submission_id)
        manifest["status"] = status
        self._put_status(submission_id, manifest)

    def mark_email_done(self, submission_id: str, email_dir: str) -> None:
        """Record that one email dir of this submission was fully ingested, so a
        crash-and-retry of the same submission does not create a duplicate case
        for it. Durable (lives in the submission's own _status.json)."""
        manifest = self.read_status(submission_id)
        done = manifest.get("processed_emails") or []
        if email_dir not in done:
            done.append(email_dir)
            manifest["processed_emails"] = done
            self._put_status(submission_id, manifest)

    def download_submission(self, submission_id: str, dest_root: str) -> str | None:
        from tasp.cron.utils import _safe_object_name

        prefix = f"{submission_id}/"
        local_root = os.path.join(dest_root, submission_id)
        os.makedirs(local_root, exist_ok=True)
        wrapper_path: str | None = None

        for obj in self._client.list(self._bucket, prefix, True):
            rel = obj.name[len(prefix):]
            if not rel or rel == sc.STATUS_OBJECT_NAME:
                continue
            try:
                safe_rel = _safe_object_name(rel)
            except ValueError:
                logger.warning("Unsafe object name %r in %s, skipped",
                               obj.name, submission_id)
                continue
            dst = os.path.join(local_root, safe_rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            self._client.download(self._bucket, obj.name, dst)
            if obj.name.endswith(sc.SUBMISSION_EML_SUFFIX):
                wrapper_path = dst

        return wrapper_path
