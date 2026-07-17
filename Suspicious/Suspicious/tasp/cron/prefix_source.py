"""Read the portable feeder contract: one bucket, prefix-per-submission.

Lists submission prefixes under a single feeder bucket and drives each
submission's status via its `_status.json` object — the portable replacement
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
        resp = self._client.get_object(self._bucket, self._status_key(submission_id))
        try:
            return sc.parse_status(resp.read())
        finally:
            close = getattr(resp, "close", None)
            release = getattr(resp, "release_conn", None)
            if callable(close):
                close()
            if callable(release):
                release()

    def iter_pending(self) -> Iterator[str]:
        for obj in self._client.list_objects(self._bucket, recursive=False):
            name = obj.object_name
            if not name.endswith("/"):
                continue
            submission_id = name.rstrip("/")
            try:
                status = self.read_status(submission_id)
            except Exception:
                logger.warning("No/invalid _status.json for %s — skipping", submission_id)
                continue
            if status.get("status") in (sc.STATUS_TODO, sc.STATUS_PROCESSING):
                yield submission_id

    def _put_status(self, submission_id: str, manifest: dict) -> None:
        raw = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        self._client.put_object(
            bucket_name=self._bucket,
            object_name=self._status_key(submission_id),
            data=io.BytesIO(raw),
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

        for obj in self._client.list_objects(self._bucket, prefix=prefix, recursive=True):
            rel = obj.object_name[len(prefix):]
            if not rel or rel == sc.STATUS_OBJECT_NAME:
                continue
            try:
                safe_rel = _safe_object_name(rel)
            except ValueError:
                logger.warning("Unsafe object name %r in %s — skipped",
                               obj.object_name, submission_id)
                continue
            dst = os.path.join(local_root, safe_rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            self._client.fget_object(self._bucket, obj.object_name, dst)
            if obj.object_name.endswith(sc.SUBMISSION_EML_SUFFIX):
                wrapper_path = dst

        return wrapper_path
