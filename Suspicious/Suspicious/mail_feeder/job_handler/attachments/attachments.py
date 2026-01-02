import logging
import os
from typing import List, Tuple
from django.db import transaction

from settings.models import AllowListFile, AllowListFiletype
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from .models import FileModel, HashModel
from .utils import safe_execution
from hash_process.hash_utils.hash_handler import HashHandler
from file_process.file_utils.file_handler import FileHandler

from hash_process.models import Hash
from file_process.models import File

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class AttachmentJobLauncherService:
    """
    Service to launch Cortex jobs for attachments and hashes.
    """

    def __init__(self):
        self.job_ids: List[int] = []
        self.artifact_id: int | None = None

    def process_attachment(self, file_model: FileModel) -> Tuple[List[int], int | None]:
        """
        Main entry point to process a file attachment.
        """
        with safe_execution("process_attachment"):
            fetch_mail_logger.debug(f"Processing attachment file: {file_model.file_path}")
            hash_value = self.compute_file_hash(file_model)
            if hash_value is None:
                fetch_mail_logger.warning(f"Failed to compute hash for file: {file_model.file_path}")
                return self.job_ids, self.artifact_id
            fetch_mail_logger.debug(f"Computed hash {hash_value} for file: {file_model.file_path}")
            self.handle_hash_and_file(file_model, hash_value)
            fetch_mail_logger.debug(f"Completed processing for file: {file_model.file_path} with jobs: {self.job_ids}")
            return self.job_ids, self.artifact_id

    def compute_file_hash(self, file_model: FileModel) -> str | None:
        """
        Compute the hash of a file.
        """
        with safe_execution("compute_file_hash"):
            return FileHandler.hash_file(file_model.tmp_path)

    def handle_hash_and_file(self, file_model: FileModel, hash_value: str):
        """
        Handle linking or creating hash and associating it with the file.
        """
        with safe_execution("handle_hash_and_file"):
            existing_hashes = list(Hash.objects.filter(value=hash_value)) or []
            existing_files = list(File.objects.filter(file_path=file_model.file_path)) or []
            self._process_attachment_list(file_model, existing_files, existing_hashes, hash_value)

    def _process_attachment_list(
        self, file_model: FileModel, existing_files: List[FileModel], existing_hashes: List[HashModel], hash_value: str
    ):
        """
        Decide action based on existence of file and hash.
        """
        with safe_execution("process_attachment_list"):
            if existing_files and not existing_hashes:
                self._rename_file_attachment(file_model, existing_files)
            elif existing_hashes:
                self._link_existing_hash_to_file(file_model, existing_hashes[0])
            else:
                self._create_and_link_new_hash(file_model, hash_value)

    def _rename_file_attachment(self, file_model: FileModel, existing_files: List[FileModel]):
        """
        Rename the attachment to prevent name conflicts.
        """
        with safe_execution("rename_file_attachment"):
            name, ext = os.path.splitext(file_model.file_path)
            tmp_name, tmp_ext = os.path.splitext(file_model.tmp_path)
            new_name = f"{name}-{len(existing_files)}{ext}"
            new_tmp = f"{tmp_name}-{len(existing_files)}{tmp_ext}"
            if os.path.exists(file_model.tmp_path):
                os.rename(file_model.tmp_path, new_tmp)
                file_model.file_path = new_name
                file_model.tmp_path = new_tmp

    def _link_existing_hash_to_file(self, file_model: FileModel, hash_model: HashModel):
        """
        Link an existing hash to the file and decide on Cortex jobs or allowlisting.
        """
        with safe_execution("link_existing_hash_to_file"):
            file_model.linked_hash_id = hash_model.id
            file_model.save()
            self._process_jobs_or_allowlist(file_model, hash_model)

    def _create_and_link_new_hash(self, file_model: FileModel, hash_value: str):
        """
        Create a new hash object and link it to the file.
        """
        with safe_execution("create_and_link_new_hash"):
            hash_obj = HashHandler().handle_hash(hash_value)
            file_model.linked_hash_id = hash_obj.id
            file_model.save()
            self._process_jobs_or_allowlist(file_model, hash_obj)

    def _process_jobs_or_allowlist(self, file_model: FileModel, hash_model: HashModel):
        """
        Decide whether to launch Cortex jobs or mark the file and hash as allowlisted.
        """
        ext = file_model.tmp_path.split(".")[-1]
        file_model.tmp_path = file_model.tmp_path.replace("/tmp/", "")
        file_model.save()

        if not AllowListFile.objects.filter(linked_file_hash=hash_model).exists() \
           and not AllowListFiletype.objects.filter(filetype=ext).exists():
            self._launch_cortex_jobs(file_model, hash_model)
        else:
            self._allowlist_file_and_hash(file_model, hash_model)

    def _launch_cortex_jobs(self, file_model: FileModel, hash_model: HashModel):
        """
        Launch Cortex jobs for the file and its hash.
        """
        with safe_execution("launch_cortex_jobs"):
            cortex = CortexJob()
            self.job_ids.extend(cortex.launch_cortex_jobs(file_model, "file"))
            self.job_ids.extend(cortex.launch_cortex_jobs(hash_model, "hash"))

    def _allowlist_file_and_hash(self, file_model: FileModel, hash_model: HashModel):
        """
        Mark file and hash as safe and allowlisted.
        """
        with safe_execution("allowlist_file_and_hash"):
            fetch_mail_logger.info(f"File {file_model.file_path} is allow-listed")
            file_model.file_score = 0
            file_model.file_confidence = 100
            file_model.file_level = "SAFE-ALLOW_LISTED"

            hash_model.ioc_score = 0
            hash_model.ioc_confidence = 100
            hash_model.ioc_level = "SAFE-ALLOW_LISTED"

            hash_model.save()
            file_model.tmp_path = "/tmp/" + file_model.tmp_path
            file_model.save()
