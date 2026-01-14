import os
import re
import logging
from typing import List, Set, Dict, BinaryIO
from .models import Artifact, ObservablesResult

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
def add_artifact(artifacts: List[Artifact], data_type: str, data: str, tags: List[str] | None = None) -> None:
    artifact = Artifact(dataType=data_type, data=data, tags=tags)
    artifacts.append(artifact)

def add_file_attachment(
    files: Dict[str, BinaryIO],
    processed_files: Set[str],
    artifacts: List[Artifact],
    file_path: str,
    attachment_id: int,
    tags: List[str] | None = None
) -> int:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Attachment not found: {file_path}")

    if file_path not in processed_files:
        processed_files.add(file_path)
        files[str(attachment_id)] = open(file_path, "rb")
        add_artifact(artifacts, "file", str(attachment_id), tags)
        return attachment_id + 1
    return attachment_id

def process_attachments(
    directory: str,
    attachment_id: int,
    artifacts: List[Artifact],
    files: Dict[str, BinaryIO],
    processed_files: Set[str],
    tags: List[str] | None = None
) -> int:
    if not os.path.exists(directory):
        return attachment_id

    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.is_file() and not re.match(r"\d{6}-[0-9a-f]{5}\.eml", entry.name):
                file_path = os.path.join(directory, entry.name)
                attachment_id = add_file_attachment(files, processed_files, artifacts, file_path, attachment_id, tags)
    return attachment_id
