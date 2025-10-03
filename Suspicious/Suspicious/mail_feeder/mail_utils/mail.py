import os, shutil
from typing import List
from mail_feeder.processor.email_processor import parse_email
from hash_process.models import Hash
from file_process.models import File
from domain_process.models import Domain
from settings.models import AllowListFile, AllowListFiletype, AllowListDomain
from mail_feeder.models import MailArchive, MailArtifact, MailAttachment, MailInfo
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from ip_process.ip_utils.ip_handler import IPHandler
from url_process.url_utils.url_handler import URLHandler
from domain_process.domain_utils.domain_handler import DomainHandler
from hash_process.hash_utils.hash_handler import HashHandler
from email_process.email_utils.email_handler import MailAddressHandler, get_domain, _create_or_update_domain
from file_process.file_utils.file_handler import FileHandler
from mail_feeder.mail_utils.mail_handler import MailHandler
from score_process.score_utils.send_mail import user_acknowledge
from case_handler.case_utils.case_creator import CaseCreator
import email
from email.utils import parseaddr
import logging
import json

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})
EMAIL_WORKDIR = "/tmp/emailAnalysis/"
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)


class EmailHandler:
    def __init__(self):
        self.workdir = EMAIL_WORKDIR


class ArtifactHandler:
    def __init__(self):
        self.ids = []
        self.list_artifacts = []

    def handle_artifact(self, artifacts):
        """
        Handles the given artifacts by calling the appropriate handler based on the artifact type.

        Args:
            artifacts (QuerySet): A queryset of artifacts.

        Returns:
            list: A list of artifact IDs that were successfully handled.
        """
        handlers = {
            "IP": self.handle_ip_artifact,
            "Hash": self.handle_hash_artifact,
            "URL": self.handle_url_artifact,
            "Domain": self.handle_domain_artifact,
            "MailAddress": self.handle_mail_artifact,
        }

        for artifact in artifacts.all():
            handler = handlers.get(artifact.artifact_type)
            if handler:
                try:
                    handler(artifact)
                except Exception as e:
                    fetch_mail_logger.error(
                        f"Failed to handle {artifact.artifact_type} artifact. Reason: {e}"
                    )
            else:
                fetch_mail_logger.warning(
                    f"No handler for artifact type {artifact.artifact_type}"
                )

        return self.ids

    def handle_ip_artifact(self, artifact):
        """
        Handles the IP artifact.

        Args:
            artifact: The IP artifact to be handled.

        Returns:
            The processed IP or None if an exception occurs.
        """
        if artifact.artifactIsIp:
            artifact_is_ip = artifact.artifactIsIp.ip
            try:
                fetch_mail_logger.info(f"Artifact is IP: {artifact_is_ip.address}")
                self.ids += CortexJob().launch_cortex_jobs(artifact_is_ip, "ip")
                return artifact_is_ip
            except Exception as e:
                fetch_mail_logger.error(f"Failed to handle IP artifact. Reason: {e}")
                return None

    def handle_hash_artifact(self, artifact):
        """
        Handles a hash artifact.

        Args:
            artifact: The artifact object containing the hash.

        Returns:
            The processed artifact hash.

        Raises:
            Exception: If there is an error while handling the hash artifact.
        """
        if artifact.artifactIsHash:
            artifact_is_hash = artifact.artifactIsHash.hash
            try:
                if hasattr(artifact_is_hash, "linked_file_hash"):
                    # Check if the hash is linked to a file and allow_listed
                    is_allow_listed = AllowListFile.objects.filter(
                        linked_file_hash=artifact_is_hash
                    ).exists()

                    if is_allow_listed:
                        fetch_mail_logger.info(f"Hash {artifact_is_hash} is allow_listed")
                        artifact_is_hash.ioc_score = 0
                        artifact_is_hash.ioc_confidence = 100
                        artifact_is_hash.ioc_level = "SAFE-ALLOW_LISTED"
                        artifact_is_hash.save()
                        return artifact_is_hash

                # For non-file-linked hashes or if not allow_listed, proceed with Cortex jobs
                self.ids += CortexJob().launch_cortex_jobs(artifact_is_hash, "hash")
            except Exception as e:
                fetch_mail_logger.error(f"Failed to handle hash artifact. Reason: {e}")
                return None

    def handle_url_artifact(self, artifact):
        """
        Handles a URL artifact.

        Args:
            artifact: The URL artifact to handle.

        Returns:
            The processed URL or None if an error occurred.
        """
        handler = URLHandler()
        if artifact.artifactIsUrl:
            artifact_is_url = artifact.artifactIsUrl.url
            try:
                domain_str = handler.get_domain(artifact_is_url.address)
                if not domain_str:
                    fetch_mail_logger.warning(f"Invalid URL: {artifact_is_url.address}")
                    return None
                domain = Domain.objects.filter(value=domain_str).first()
                if artifact_is_url:
                    if AllowListDomain.objects.filter(domain=domain).exists():
                        fetch_mail_logger.info(f"URL {artifact_is_url.address} is allow_listed")
                        artifact_is_url.ioc_score = 0
                        artifact_is_url.ioc_confidence = 100
                        artifact_is_url.ioc_level = "SAFE-ALLOW_LISTED"
                    else:
                        # sanitize the url to remove any query parameters
                        self.ids += CortexJob().launch_cortex_jobs(artifact_is_url, "url")
                    artifact_is_url.save()
                else:
                    fetch_mail_logger.warning(f"Invalid URL: {artifact_is_url.address}")
                return artifact_is_url
            except Exception as e:
                fetch_mail_logger.error(f"Failed to handle URL artifact. Reason: {e}")
                return None

    def handle_domain_artifact(self, artifact):
        """
        Handles a domain artifact.

        Args:
            artifact: The domain artifact to be handled.

        Returns:
            The processed domain if successful, None otherwise.
        """
        if artifact.artifactIsDomain:
            artifact_is_domain = artifact.artifactIsDomain.domain
            try:
                if artifact_is_domain:
                    if AllowListDomain.objects.filter(domain=artifact_is_domain).exists():
                        fetch_mail_logger.info(f"Domain {artifact_is_domain} is allow_listed")
                        artifact_is_domain.ioc_score = 0
                        artifact_is_domain.ioc_confidence = 100
                        artifact_is_domain.ioc_level = "SAFE-ALLOW_LISTED"
                    else:
                        self.ids += CortexJob().launch_cortex_jobs(artifact_is_domain, "domain")
                    artifact_is_domain.save()
                else:
                    fetch_mail_logger.warning(f"Invalid domain: {artifact_is_domain}")
                return artifact_is_domain
            except Exception as e:
                fetch_mail_logger.error(
                    f"Failed to handle domain artifact. Reason: {e}"
                )
                return None

    def handle_mail_artifact(self, artifact):
        """
        Handles a mail artifact.

        Args:
            artifact: The mail artifact to be handled.

        Returns:
            The handled mail object, or None if handling fails.
        """
        if artifact.artifactIsMailAddress:
            artifact_is_mail_address = artifact.artifactIsMailAddress.mail_address
            try:
                if artifact_is_mail_address:
                    if not artifact_is_mail_address.is_internal:
                        domain = get_domain(artifact_is_mail_address)
                        domain_instance = _create_or_update_domain(domain)
                        if domain_instance:
                            if AllowListDomain.objects.filter(domain=domain_instance).exists():
                                fetch_mail_logger.info(f"Domain {domain} is allow_listed")
                                domain_instance.ioc_score = 0
                                domain_instance.ioc_confidence = 100
                                domain_instance.ioc_level = "SAFE-ALLOW_LISTED"
                                artifact_is_mail_address.ioc_score = 0
                                artifact_is_mail_address.ioc_confidence = 100
                                artifact_is_mail_address.ioc_level = "SAFE-ALLOW_LISTED"
                                domain_instance.save()
                            else:
                                self.ids += CortexJob().launch_cortex_jobs(artifact_is_mail_address, "mail")
                        artifact_is_mail_address.save()
                    else:
                        fetch_mail_logger.warning(f"Mail address is internal: {artifact_is_mail_address}")
                return artifact_is_mail_address
            except Exception as e:
                fetch_mail_logger.error(f"Failed to handle mail artifact. Reason: {e}")
                return None


class AttachmentHandler:
    def __init__(self):
        self.ids = []
        self.id_ai = None

    def handle_attachment(self, att: File):
        """
        Handles the attachment file.

        Args:
            att (File): The attachment file to be handled.

        Returns:
            list: The list of attachment IDs.

        Raises:
            Exception: If there is an error while handling the attachment.
        """
        try:
            hash_of_file = self.hash_file(att.file)
            if hash_of_file is None:
                fetch_mail_logger.info("No hash generated for the file.")
                return self.ids, self.id_ai
            else:
                self.handle_hash_and_attachment(att.file, hash_of_file)
                return self.ids, self.id_ai
        except Exception as e:
            fetch_mail_logger.error(f"Failed to handle attachment. Reason: {e}")
            # Propagate the exception for better error handling
            raise e

    def hash_file(self, att: File):
        """
        Hashes the given file.

        Args:
            att (File): The file to be hashed.

        Returns:
            str: The hash value of the file.

        Raises:
            Exception: If there is an error while hashing the file.
        """
        try:
            return FileHandler.hash_file(att.tmp_path)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to hash file. Reason: {e}")
            # Propagate the exception for better error handling
            raise e

    def handle_hash_and_attachment(self, att: File, hash_of_file: str):
        """
        Handles the hash and attachment by querying the database for hashes and files,
        converting the querysets to lists, and then calling the `handle_attachment_list` method.

        Args:
            att (File): The attachment file object.
            hash_of_file (str): The hash value of the file.

        Raises:
            Exception: If there is an error handling the attachment.

        """
        try:
            # Query the database for hashes and files
            hashlist = Hash.objects.filter(value=hash_of_file)
            attlist = File.objects.filter(file_path=att.file_path)

            # Convert to list only if the querysets are not empty
            hashlist = list(hashlist) if hashlist.exists() else []
            attlist = list(attlist) if attlist.exists() else []

            # Handle the attachment list
            self.handle_attachment_list(att, attlist, hashlist, hash_of_file)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to handle hash and attachment. Reason {e}")
            # Propagate the exception for better error handling
            raise e

    def handle_attachment_list(
        self, att: File, attlist: List[File], hashlist: List[Hash], hash_of_file: str
    ):
        """
        Handles the attachment list by performing various operations based on the provided parameters.

        Args:
            att (File): The main attachment file.
            attlist (List[File]): A list of additional attachment files.
            hashlist (List[Hash]): A list of hash objects.
            hash_of_file (str): The hash of the main attachment file.

        Raises:
            Exception: If any error occurs during the handling of the attachment list.

        Returns:
            None
        """
        try:
            if attlist and not hashlist:
                self.rename_attachment(att, attlist)
            elif hashlist:
                self.link_hash_to_attachment(att, hashlist[0])
            else:
                self.create_and_link_hash_to_attachment(att, hash_of_file)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to handle attachment list. Reason: {e}")
            raise  # Propagate the exception for better error handling

    def rename_attachment(self, att: File, attlist: List[File]):
        """
        Renames the given attachment and updates its temporary path.

        Args:
            att (File): The attachment to be renamed.
            attlist (List[File]): The list of attachments.

        Raises:
            Exception: If there is an error while renaming the attachment.

        Returns:
            None
        """
        try:
            # Split the file name and extension
            name, ext = os.path.splitext(att.file_path.name)
            tmp_name, tmp_ext = os.path.splitext(att.tmp_path)

            # Create a new name by appending the length of attlist
            att_name = f"{name}-{len(attlist)}{ext}"
            tmp_path = f"{tmp_name}-{len(attlist)}{tmp_ext}"

            # Check if the file exists before renaming
            if os.path.exists(att.tmp_path):
                att.file_path.name = att_name
                os.rename(att.tmp_path, tmp_path)
                att.tmp_path = tmp_path
        except Exception as e:
            fetch_mail_logger.error(f"Failed to rename attachment. Reason: {e}")
            raise e  # Propagate the exception for better error handling

    def link_hash_to_attachment(self, att: File, hash: Hash):
        """
        Links a hash to an attachment.

        Args:
            att (File): The attachment to link the hash to.
            hash (Hash): The hash to be linked.

        Raises:
            Exception: If the linking process fails.

        Returns:
            None
        """
        try:
            att.linked_hash = hash
            att.save()
            fetch_mail_logger.info(
                f"Successfully linked hash {hash} to attachment {att.file_path}"
            )
            self.launch_jobs_and_handle_exceptions(
                att, hash
            )  # Launch the job after linking
        except Exception as e:
            fetch_mail_logger.error(f"Failed to link hash to attachment. Reason: {e}")
            raise e  # Propagate the exception for better error handling

    def create_and_link_hash_to_attachment(self, att: File, hash_of_file: str):
        """
        Creates and links a hash to the given attachment.

        Args:
            att (File): The attachment file object.
            hash_of_file (str): The hash of the file.

        Raises:
            Exception: If there is an error creating and linking the hash to the attachment.

        """
        try:
            hash_handler = HashHandler()
            hash_attachment = hash_handler.handle_hash(hash_of_file)
            att.linked_hash = hash_attachment
            att.save()
            if hash_attachment:
                self.launch_jobs_and_handle_exceptions(att, hash_attachment)
        except Exception as e:
            fetch_mail_logger.error(
                f"Failed to create and link hash to attachment. Reason: {e}"
            )
            raise e  # Propagate the exception for better error handling

    def launch_jobs_and_handle_exceptions(self, att: File, hash: Hash):
        """
        Launches jobs or allow_lists the attachment file and handles any exceptions that occur.

        Args:
            att (File): The attachment file.
            hash (Hash): The hash of the attachment file.

        Raises:
            Exception: If there is an error while launching the attachment file job.

        """
        try:
            ext = att.tmp_path.split(".")[-1]
            att.tmp_path = att.tmp_path.replace("/tmp/", "")
            att.save()
            self.launch_jobs_or_allow_list(att, hash, ext)
        except Exception as e:
            fetch_mail_logger.error(
                f"Failed to launch att file job. Reason {e}"
            ) 
            raise e 

    def launch_jobs_or_allow_list(self, att: File, hash: Hash, ext: str):
        """
        Launches jobs or allow_lists the file and hash based on certain conditions.

        Args:
            att (File): The file object to be processed.
            hash (Hash): The hash object associated with the file.
            ext (str): The file extension.

        Raises:
            Exception: If there is an error while launching jobs or allow_listing.

        """
        try:
            if (
                not AllowListFile.objects.filter(
                    linked_file_hash=att.linked_hash
                ).exists()
                and not AllowListFiletype.objects.filter(filetype=ext).exists()
            ):
                self.launch_jobs(att, hash)
            else:
                self.allow_list_file_and_hash(att, hash)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to launch jobs or allow_list. Reason: {e}")

    def launch_jobs(self, att: File, hash: Hash):
        """
        Launches Cortex jobs for the given attachment and hash.

        Args:
            att (File): The attachment file to be processed.
            hash (Hash): The hash value to be processed.

        Returns:
            None

        Raises:
            Exception: If there is an error while launching the Cortex jobs.
        """
        cortex_job = CortexJob()
        try:
            fetch_mail_logger.info(f"Launching cortex jobs for file {att.file_path}")
            self.ids.extend(cortex_job.launch_cortex_jobs(att, "file"))
        except Exception as e:
            fetch_mail_logger.error(f"Failed to launch file job. Reason {e}")
        try:
            self.ids.extend(cortex_job.launch_cortex_jobs(hash, "hash"))
        except Exception as e:
            fetch_mail_logger.error(f"Failed to launch hash job. Reason {e}")

    def allow_list_file_and_hash(self, att: File, hash: Hash):
        """
        AllowLists a file and its hash.

        Args:
            att (File): The file to be allow_listed.
            hash (Hash): The hash of the file.

        Returns:
            None
        """
        fetch_mail_logger.info(f"File {att.file_path} is allow_listed")
        att.file_score = 0
        att.file_confidence = 100
        att.file_level = "SAFE-ALLOW_LISTED"
        hash.ioc_score = 0
        hash.ioc_confidence = 100
        hash.ioc_level = "SAFE-ALLOW_LISTED"
        hash.save()
        att.tmp_path = "/tmp/" + att.tmp_path
        att.save()


class EmailProcessor:
    def __init__(self, email_handler: EmailHandler):
        self.email_handler = email_handler
        self.fetched_mails = []
        self.ids = []
        self.uploader = None  # Initialize without an uploader

    def create_case(
        self, instance, user, artifact_ids, attachment_ids, attachment_id_ai, list_ids
    ):
        """
        Create a case using the provided instance, user, artifact IDs, attachment IDs, and list IDs.

        Args:
            instance: The mail instance.
            user: The user creating the case.
            artifact_ids: A list of artifact IDs.
            attachment_ids: A list of attachment IDs.
            list_ids: A list of IDs to append to.

        Returns:
            None
        """
        # Simplify the process of appending ids to list_ids
        list_ids.extend(artifact_ids)
        list_ids.extend(id for sublist in attachment_ids for id in sublist)

        # Use dictionary comprehension to create _dict
        _dict = {
            key: None
            for key in [
                "file_instance",
                "ip_instance",
                "url_instance",
                "hash_instance",
                "mail_instance",
            ]
        }
        _dict["mail_instance"] = instance
        user = MailHandler().get_or_create_user(user)
        # Use context manager to ensure case is saved even if an error occurs
        case_creator = CaseCreator(user)
        try:
            case = case_creator.create_case(**_dict)
            if case and case.fileOrMail:
                case.fileOrMail.mail = instance
                case.save()
        except Exception as e:
            fetch_mail_logger.error(f"Failed to create and save case. Reason: {e}")

    def process_emails_from_web_submission(self, workdir, user):
        """
        Process all emails submitted via a web form within the given working directory.

        Args:
            workdir (str): Directory containing submitted email files.
            user (str): Email address of the user who submitted the email.

        Returns:
            instance (MailInstance or None): Last processed mail instance or None if failed.
        """
        email_id = os.path.basename(workdir)
        try:
            fetch_mail_logger.info(f"Processing submitted emails in {workdir}")
            eml_files = self._list_eml_files(workdir, prefix="user_submission")
            last_instance = None
            for filename in eml_files:
                fetch_mail_logger.debug(f"Processing submitted email file {filename}")
                last_instance = self._process_single_email(workdir, filename, email_id, user, is_submitted=True)
            return last_instance
        except Exception as e:
            fetch_mail_logger.error(f"Failed to process submitted emails {email_id}: {e}")
            return None

    def process_emails_from_minio_workdir(self, workdir):
        """
        Process all regular emails present in the given MinIO work directory.

        Args:
            workdir (str): Path to the email directory in MinIO.
        """
        email_id = os.path.basename(workdir)
        try:
            fetch_mail_logger.info(f"Processing MinIO emails in {workdir}")
            eml_files = self._list_eml_files(workdir, exclude_prefix="user_submission")
            for filename in eml_files:
                fetch_mail_logger.debug(f"Processing MinIO email file {filename}")
                self._process_single_email(workdir, filename, email_id, user=None, is_submitted=False)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to process MinIO emails {email_id}: {e}")

    def _list_eml_files(self, directory, prefix=None, exclude_prefix=None):
        """
        List all .eml files in a directory, optionally filtering by prefix.

        Args:
            directory (str): Directory to search.
            prefix (str, optional): Only include files starting with this prefix.
            exclude_prefix (str, optional): Exclude files starting with this prefix.

        Returns:
            list[str]: List of matching filenames.
        """
        return [
            f for f in os.listdir(directory)
            if f.endswith(".eml") and
               (not prefix or f.startswith(prefix)) and
               (not exclude_prefix or not f.startswith(exclude_prefix))
        ]
        
    
    def create_mail_info(self, mail_instance):
        """
        Creates a MailInfo object and saves it to the database.

        Args:
            mail_instance (Mail): The mail instance to create MailInfo for.

        Returns:
            None
        """
        try:
            _, origin_mail = parseaddr(mail_instance.reportedBy)
            fetch_mail_logger.info(f"Reported by: {origin_mail}")
            # Retrieve or create the user associated with the mail
            user = MailHandler().get_or_create_user(origin_mail)
            
            # Initialize the MailInfo object
            reception_ok = MailInfo(
                user=user,
                mail=mail_instance,
                is_received=True
            )

            # Set is_phishing flag if mail has been sent multiple times
            if mail_instance.times_sent >= 15:
                reception_ok.is_phishing = True
                
            # Save the MailInfo instance
            reception_ok.save()
            
            # Call the acknowledgment function
            user_acknowledge(reception_ok)
            
        except Exception as e:
            fetch_mail_logger.error(f"Error creating MailInfo: {str(e)}")

    def _process_single_email(self, workdir, filename, email_id, user, is_submitted):
        """
        Process a single email file, parsing and saving it to the system.

        Args:
            workdir (str): Directory containing the email file.
            filename (str): Name of the email file.
            email_id (str): Unique ID representing the email session.
            user (str or None): Reporter’s email address if submitted via web.
            is_submitted (bool): Whether the email came from a web submission.

        Returns:
            instance (MailInstance or None): Parsed and handled mail instance.
        """
        try:
            filepath = os.path.join(workdir, filename)
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f)

            mail_instance = parse_email(msg, workdir, email_id, user if is_submitted else None)
            handler = MailHandler()
            instance = handler.handle_mail(mail_instance, workdir)

            if instance:
                if is_submitted:
                    self._handle_instance_for_web_submission(instance, email_id, workdir, user)
                else:
                    self._handle_instance_for_minio(instance, email_id, workdir)
                self.create_mail_info(instance)
            else:
                fetch_mail_logger.error(f"Email instance processing failed for {email_id}")
            return instance
        except Exception as e:
            fetch_mail_logger.error(f"Error processing email {email_id}: {e}")
            return None

    def _handle_instance_for_web_submission(self, instance, email_id, workdir, user):
        """
        Handle finalization of an email instance submitted via web.

        Args:
            instance: Mail object to finalize.
            email_id (str): Email identifier.
            workdir (str): Working directory path.
            user (str): Email address of the reporter.
        """
        try:
            instance.reportedBy = user
            instance.save()
            mail_zip = self._get_mail_zip_path(workdir, email_id)
            self._handle_common_instance_tasks(instance, email_id, mail_zip)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to finalize web submission for {email_id}: {e}")

    def _handle_instance_for_minio(self, instance, email_id, workdir):
        """
        Handle finalization of a MinIO-parsed email instance.

        Args:
            instance: Mail object to finalize.
            email_id (str): Email identifier.
            workdir (str): Working directory path.
        """
        try:
            user_email = self._extract_reported_by_from_user_submission(workdir)
            instance.reportedBy = user_email
            instance.save()
            mail_zip = self._get_mail_zip_path(workdir, email_id)
            self._handle_common_instance_tasks(instance, email_id, mail_zip)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to finalize MinIO email for {email_id}: {e}")

    def _extract_reported_by_from_user_submission(self, workdir):
        """
        Extracts the sender email address from 'user_submission.eml' file.

        Args:
            workdir (str): Directory containing the 'user_submission.eml' file.

        Returns:
            str or None: Parsed email address or None on failure.
        """
        try:
            path = os.path.join(workdir, "user_submission.eml")
            with open(path, "r") as f:
                user_submission = email.message_from_file(f)
            _, email_addr = parseaddr(user_submission.get("From"))
            return email_addr
        except Exception as e:
            fetch_mail_logger.error(f"Unable to extract reportedBy: {e}")
            return None

    def _get_mail_zip_path(self, workdir, email_id):
        """
        Compute path to the archived .tar.gz email file.

        Args:
            workdir (str): Working directory of the email.
            email_id (str): Email session ID.

        Returns:
            str: Full path to the archive.
        """
        return os.path.join(os.path.dirname(workdir), f"{email_id}.tar.gz")

    def _handle_common_instance_tasks(self, instance, email_id, mail_zip):
        """
        Handle all post-processing tasks shared between web and MinIO email types.

        Args:
            instance: Parsed Mail object instance.
            email_id (str): Email session ID.
            mail_zip (str): Path to archive file.
        """
        handler = MailHandler()
        user = handler.get_or_create_user(instance.reportedBy)

        artifact_ids = self.handle_artifacts(instance)
        attachment_ids, attachment_id_ai = self.handle_attachments(instance, mail_zip)

        self.handle_mail_header(instance)
        self.handle_mail_body(instance, email_id)

        related_ids = self.combine_ids(artifact_ids, attachment_ids)
        self.create_case(instance, user, artifact_ids, attachment_ids, attachment_id_ai, related_ids)

    def handle_artifacts(self, instance):
        """
        Handles the artifacts associated with the given instance.

        Args:
            instance: The instance for which the artifacts need to be handled.

        Returns:
            A list of handled artifacts.

        Raises:
            Exception: If there is an error while handling the artifacts.
        """
        artifact_handler = ArtifactHandler()
        artifact_ids = []
        instance_artifacts = MailArtifact.objects.filter(mail=instance)
        try:
            if instance_artifacts:
                artifact_ids = artifact_handler.handle_artifact(instance_artifacts)
        except Exception as e:
            fetch_mail_logger.error(f"Error while handling artifacts: {str(e)}")
        return artifact_ids

    def handle_attachments(self, instance, mail_zip):
        """
        Handles the attachments of an instance.

        Args:
            instance: The instance for which attachments need to be handled.

        Returns:
            A list of attachment IDs that were successfully handled.
        """
        attachment_handler = AttachmentHandler()
        attachment_ids = []
        attachment_id_ai = []
        instance_attachments = MailAttachment.objects.filter(mail=instance)
        for att in instance_attachments:
            if att:
                try:
                    ids, id_ai = attachment_handler.handle_attachment(att)
                    if ids:
                        attachment_ids.append(ids)
                    if id_ai:
                        attachment_id_ai.append(id_ai)
                except Exception as e:
                    fetch_mail_logger.error(f"Failed to handle attachments. Reason {e}")
                    continue
        # Process instance.zip as an attachment if it exists
        if mail_zip:
            mail_archive = MailArchive.objects.filter(mail=instance).first()
            if not mail_archive:
                archive, _ = FileHandler.handle_file(file=None, mail=mail_zip)
                mail_archive = MailArchive.objects.create(mail=instance, archive=archive)

            try:
                cortex_job = CortexJob()
                id_ai = cortex_job.launch_cortex_ai_jobs(mail_archive, "file")
                if id_ai:
                    attachment_id_ai.append(id_ai)
            except Exception as e:
                fetch_mail_logger.error(f"Failed to handle attachments ai. Reason {e}")
        return attachment_ids, attachment_id_ai

    def handle_mail_header(self, instance):
        """
        Handles the mail header of the given instance.

        Args:
            instance: The instance containing the mail header.

        Returns:
            None
        """
        # Check if instance has a mail_header attribute
        if hasattr(instance, "mail_header"):
            # Initialize CortexJob handler
            handler = CortexJob()
            # Check if mail_header is not None or empty
            if instance.mail_header:
                try:
                    # Launch cortex jobs for mail_header
                    handler.launch_cortex_jobs(instance.mail_header, "mail_header")
                except Exception as e:
                    # Log the exception and continue
                    fetch_mail_logger.error(
                        f"Error while handling mail header: {str(e)}"
                    )
                else:
                    fetch_mail_logger.info("Successfully handled mail header.")
        else:
            fetch_mail_logger.warning("Instance does not have a mail_header attribute.")

    def handle_mail_body(self, instance, email_id):
        """
        Handles the mail body by writing it to a file and launching Cortex jobs.

        Args:
            instance: The instance of the mail.
            email_id: The ID of the email.

        Returns:
            None
        """
        handler = CortexJob()
        try:
            if instance.mail_body:
                # Create a directory for the email if it doesn't exist
                email_dir = os.path.join(self.email_handler.workdir, email_id)
                os.makedirs(email_dir, exist_ok=True)

                # Use context manager for file operations to ensure the file is closed after writing
                file_path = os.path.join(
                    email_dir, f"{instance.mail_body.fuzzy_hash}.txt"
                )
                with open(file_path, "w") as f:
                    f.write(instance.mail_body.body_value)

                # Launch Cortex jobs and handle any exceptions
                try:
                    handler.launch_cortex_jobs(file_path, "mail_body")
                except Exception as e:
                    fetch_mail_logger.error(f"Error launching Cortex jobs: {e}")
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail body: {e}")

    def combine_ids(self, artifact_ids, attachment_ids):
        """
        Combines the given artifact IDs and attachment IDs into a single list.

        Args:
            artifact_ids (list): A list of artifact IDs.
            attachment_ids (list): A list of attachment IDs.

        Returns:
            list: A combined list of artifact IDs and attachment IDs.
        """
        # Check if the input parameters are lists, if not, raise an exception
        if not isinstance(artifact_ids, list) or not isinstance(attachment_ids, list):
            raise TypeError(
                "Both artifact_ids and attachment_ids should be of type list"
            )

        # Use list comprehension to combine the lists
        list_ids = [id for sublist in [artifact_ids, attachment_ids] for id in sublist]

        return list_ids


def clean_workdir(folder):
    """
    This function cleans the working directory by deleting all files and directories within it.

    :param folder: The directory to be cleaned.
    """
    for filename in os.listdir(folder):
        fetch_mail_logger.info(f"Deleting {filename}")
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                fetch_mail_logger.info(f"Deleting file {file_path}")
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                fetch_mail_logger.info(f"Deleting directory {file_path}")
                shutil.rmtree(file_path)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to delete {file_path}. Reason: {e}")
