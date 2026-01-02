import json
import logging
import os
from datetime import datetime, timedelta

from cortex4py.api import Api
from cortex_job.models import Analyzer, AnalyzerReport
from mail_feeder.models import MailBody, MailArchive, MailInfo, MailHeader
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

# ------------------------
# Logger setup
# ------------------------
logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

# ------------------------
# Load Cortex configuration
# ------------------------
CONFIG_PATH = os.getenv("CONFIG_PATH", "/app/settings.json")
try:
    with open(CONFIG_PATH, "r") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    fetch_mail_logger.error(f"Configuration file not found at {CONFIG_PATH}")
    config = {}
except json.JSONDecodeError as e:
    fetch_mail_logger.error(f"Error parsing JSON config: {e}")
    config = {}

cortex_config = config.get("cortex", {})

# ------------------------
# API settings
# ------------------------
API_URL = cortex_config.get("url", "https://cortex.example.com")
API_KEY = cortex_config.get("api_key", "your_api_key_here")

try:
    API = Api(API_URL, API_KEY, proxies={"http": "", "https": ""})
except Exception as e:
    fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
    API = None


class CortexJob:
    def __init__(self, api_url=None, api_key=None, proxies=None):
        """
        Initialize the CortexJob with API connection.

        Args:
            api_url (str, optional): Cortex API URL. Defaults to API_URL.
            api_key (str, optional): Cortex API key. Defaults to API_KEY.
            proxies (dict, optional): Proxy configuration, e.g., {"http": "...", "https": "..."}.
        """
        self.api_url = api_url or API_URL
        self.api_key = api_key or API_KEY

        # Ensure proxies is a dict; default to empty no-proxy configuration
        self.proxies = (
            proxies if isinstance(proxies, dict) else {"http": "", "https": ""}
        )

        # Initialize Cortex API connection
        try:
            self.api = Api(self.api_url, self.api_key, proxies=self.proxies)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
            self.api = None

    def launch_cortex_jobs(self, value, data_type):
        """
        Launch Cortex jobs for the given value and data type.

        Args:
            value: The object to be analyzed (file, mail, domain, etc.).
            data_type (str): The type of data ('file', 'url', 'mail_body', etc.).

        Returns:
            list[str]: A list of job IDs for the launched Cortex jobs.
        """
        api_launchjob = self.api
        analyzers = []

        try:
            # --- FILE and MAIL_BODY special handling ---
            if data_type in ["file", "mail_body"]:
                if data_type == "mail_body":
                    yara_name = cortex_config.get("yara_analyzer")
                    yara_analyzer = api_launchjob.analyzers.get_by_name(yara_name)
                    if yara_analyzer:
                        analyzers.append(yara_analyzer)
                    else:
                        fetch_mail_logger.warning(
                            f"Yara analyzer '{yara_name}' not found"
                        )

                elif data_type == "file":
                    analyzers = CortexJob.get_file_analyzers(api_launchjob, value)

                    # Exclude analyzers for `.eml` files
                    if getattr(
                        value, "file_path", None
                    ) and value.file_path.name.endswith(".eml"):
                        excluded = {
                            cortex_config.get("ai_analyzer"),
                            cortex_config.get("yara_analyzer"),
                            cortex_config.get("sandbox_analyzer"),
                            cortex_config.get("header_analyzer"),
                        }
                        analyzers = [
                            a for a in analyzers if a and a.name not in excluded
                        ]

            # --- MAIL_HEADER handling ---
            elif data_type == "mail_header":
                header_name = cortex_config.get("header_analyzer")
                header_analyzer = api_launchjob.analyzers.get_by_name(header_name)
                if header_analyzer:
                    analyzers.append(header_analyzer)
                else:
                    fetch_mail_logger.warning(
                        f"Header analyzer '{header_name}' not found"
                    )

            # --- GENERIC TYPES (ip, domain, hash, url, mail, etc.) ---
            else:
                analyzers = CortexJob.get_analyzers_by_type(api_launchjob, data_type)

            # --- Run analyzers and collect job IDs ---
            r_ids = []
            for analyzer in analyzers:
                try:
                    report = CortexJob.run(api_launchjob, analyzer, value, data_type)
                    if report and hasattr(report, "id"):
                        r_ids.append(report.id)
                except Exception as e:
                    fetch_mail_logger.error(
                        f"Error running analyzer {analyzer.name if analyzer else 'Unknown'}: {e}"
                    )

            return r_ids

        except Exception as e:
            fetch_mail_logger.error(f"Error launching Cortex jobs for {data_type}: {e}")
            return []

    def launch_cortex_ai_jobs(self, value, data_type):
        """
        Launch Cortex AI jobs for the given value and data type.

        Args:
            value: The object to analyze (file, archive, etc.).
            data_type (str): The type of data ('file', 'mail_body', etc.).

        Returns:
            str or None: The job ID of the launched Cortex AI job, or None if launch failed.
        """
        if data_type != "file":
            return None  # Currently, only 'file' type is supported

        # Validate that the value has an archive with a tmp_path
        archive = getattr(value, "archive", None)
        if not archive or not hasattr(archive, "tmp_path"):
            fetch_mail_logger.warning(
                f"Invalid value or missing archive for data_type '{data_type}'"
            )
            return None

        # Only run AI analyzer if not a .eml file
        if archive.tmp_path.endswith(".eml"):
            fetch_mail_logger.info("Skipping AI analyzer for .eml file")
            return None

        try:
            # Get AI analyzer by name from config
            ai_analyzer_name = cortex_config.get("ai_analyzer")
            analyzer = self.api.analyzers.get_by_name(ai_analyzer_name)
            if not analyzer:
                fetch_mail_logger.warning(f"AI analyzer '{ai_analyzer_name}' not found")
                return None

            # Run analyzer using CortexJob.run
            report = CortexJob.run(self.api, analyzer, archive, "file")
            return getattr(report, "id", None)
        except Exception as e:
            fetch_mail_logger.error(f"Error launching Cortex AI job: {e}")
            return None

    @staticmethod
    def run(api, analyzer, value, data_type):
        """
        Run an analyzer on the provided value using the Cortex API.

        Args:
            api: Cortex API object.
            analyzer: Analyzer object.
            value: Data to analyze.
            data_type (str): Type of the data ('file', 'mail_body', 'url', 'ip', 'hash', etc.)

        Returns:
            The Cortex job report object if successful, None otherwise.
        """
        # Handle mail_body as 'file' internally in run_analyzer
        if data_type == "mail_body":
            return CortexJob.run_analyzer(api, analyzer, value, "mail_body")

        # Default case: run analyzer for given data_type
        return CortexJob.run_analyzer(api, analyzer, value, data_type)

    @staticmethod
    def get_file_analyzers(api, file):
        """
        Retrieve specific file analyzers from the Cortex API, with special handling for .eml files.

        Args:
            api: Cortex API object.
            file: File object, expected to have 'file_path.name' attribute.

        Returns:
            list: List of Cortex analyzer objects.
        """
        if not hasattr(file, "file_path") or not hasattr(file.file_path, "name"):
            raise TypeError("file must have 'file_path.name' attribute")

        analyzer_names = filter(
            None,
            [
                cortex_config.get("yara_analyzer"),
                cortex_config.get("file_info_analyzer"),
                cortex_config.get("sandbox_analyzer"),
            ],
        )

        analyzers = []

        for analyzer_name in analyzer_names:
            # Skip Yara analyzer for .eml files
            if analyzer_name == "Yara_3_0" and file.file_path.name.endswith(".eml"):
                continue

            try:
                analyzer = api.analyzers.get_by_name(analyzer_name)
                if analyzer:
                    analyzers.append(analyzer)
            except Exception as e:
                fetch_mail_logger.warning(
                    f"Error retrieving analyzer '{analyzer_name}': {e}"
                )

        fetch_mail_logger.debug(
            f"Retrieved {len(analyzers)} file analyzers for {file.file_path.name}"
        )
        return analyzers

    @staticmethod
    def get_analyzers_by_type(api, data_type):
        """
        Retrieve all Cortex analyzers of a given type, excluding certain configured analyzers.

        Args:
            api: Cortex API object.
            data_type (str): Type of data ('file', 'url', 'ip', 'hash', 'domain', 'mail', etc.)

        Returns:
            list: Filtered list of analyzers.
        """
        try:
            analyzers = api.analyzers.get_by_type(data_type)
        except Exception as e:
            fetch_mail_logger.error(
                f"Error fetching analyzers for type '{data_type}': {e}"
            )
            return []

        # Analyzers to exclude (safely handle missing keys in config)
        analyzers_to_remove = set(
            filter(
                None,
                [
                    cortex_config.get("yara_analyzer"),
                    cortex_config.get("sandbox_analyzer"),
                    cortex_config.get("header_analyzer"),
                ],
            )
        )

        # Filter out excluded analyzers
        filtered_analyzers = [
            analyzer
            for analyzer in analyzers
            if analyzer.name not in analyzers_to_remove
        ]

        fetch_mail_logger.debug(
            f"Retrieved {len(filtered_analyzers)} analyzers for type '{data_type}' "
            f"(excluded {len(analyzers_to_remove)})"
        )

        return filtered_analyzers

    @staticmethod
    def run_analyzer(api, analyzer, data, data_type):
        """
        Run a Cortex analyzer on the given data using the provided API.

        Args:
            api: Cortex API object.
            analyzer: Analyzer object containing `id` and `name`.
            data: The data object to analyze.
            data_type (str): Type of data ('file', 'url', 'ip', 'hash', 'domain', 'mail', 'mail_body', 'mail_header').

        Returns:
            report: The Cortex job report object if successful, None otherwise.
        """
        try:
            data_value = CortexJob.get_data_value(data, data_type)
        except Exception as e:
            fetch_mail_logger.error(f"Error extracting data value for {data_type}: {e}")
            return None

        # Prepare payload for analyzer
        payload = {
            "data": data_value,
            "dataType": "file" if data_type == "mail_body" else data_type,
            "tlp": 2,
        }

        try:
            report = api.analyzers.run_by_name(analyzer.name, payload)
        except Exception as e:
            fetch_mail_logger.error(
                f"Error running analyzer '{analyzer.name}' on {data_type}: {e}"
            )
            return None

        # Ensure Analyzer DB record exists
        analyzer_db = CortexJob.get_analyzer_db(analyzer)

        # Create AnalyzerReport entry if report was successfully returned
        if report:
            fetch_mail_logger.debug(
                f"Analyzer '{analyzer.name}' run successfully for data type '{data_type}'"
            )

            analyzer_report = AnalyzerReport(
                cortex_job_id=report.id,
                type=data_type,
                analyzer=analyzer_db,
                level="info",
                confidence=0,
                score=0,
                report_summary={"ongoing": "analysis"},
                report_full={"ongoing": "analysis"},
                report_taxonomy={"ongoing": "analysis"},
            )

            # Set specific data fields (file, url, ip, etc.)
            try:
                CortexJob.set_analyzer_report_data(analyzer_report, data, data_type)
            except Exception as e:
                fetch_mail_logger.error(f"Error setting analyzer report data: {e}")

        return report

    @staticmethod
    def get_data_value(data, data_type):
        """
        Retrieve the value of the data object based on its type.

        Args:
            data: The data object (File, URL, IP, Hash, Domain, MailBody, MailHeader, etc.)
            data_type (str): The type of the data.

        Returns:
            The value corresponding to the data_type.

        Raises:
            ValueError: If an unsupported data_type is provided.
            TypeError: If the expected attributes are missing from the data object.
        """
        if data_type == "file":
            if not hasattr(data, "tmp_path"):
                raise TypeError("File object must have 'tmp_path' attribute")
            data_value = (
                data.tmp_path if "tar.gz" in data.tmp_path else f"/tmp/{data.tmp_path}"
            )

        elif data_type in {"url", "ip", "mail"}:
            if not hasattr(data, "address"):
                raise TypeError(f"{data_type} object must have 'address' attribute")
            data_value = data.address

        elif data_type in {"hash", "domain"}:
            if not hasattr(data, "value"):
                raise TypeError(f"{data_type} object must have 'value' attribute")
            data_value = data.value

        elif data_type == "mail_body":
            data_value = data  # Pass the object or string itself

        elif data_type == "mail_header":
            if not hasattr(data, "header_value"):
                raise TypeError("MailHeader object must have 'header_value' attribute")
            data_value = data.header_value

        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        return data_value

    @staticmethod
    def get_analyzer_db(analyzer):
        """
        Retrieve an Analyzer object from the database, or create a new one if it does not exist.

        Args:
            analyzer: An object with `id` and `name` attributes representing the Cortex analyzer.

        Returns:
            Analyzer: The retrieved or newly created Analyzer instance.
        """
        if not hasattr(analyzer, "id") or not hasattr(analyzer, "name"):
            raise TypeError("analyzer must have 'id' and 'name' attributes")

        try:
            # Try fetching the Analyzer by Cortex ID
            analyzer_db = Analyzer.objects.get(analyzer_cortex_id=analyzer.id)
            return analyzer_db
        except Analyzer.DoesNotExist:
            pass

        # Attempt to create a new Analyzer
        try:
            analyzer_db = Analyzer.objects.create(
                analyzer_cortex_id=analyzer.id, name=analyzer.name, weight=0.2
            )
            return analyzer_db
        except Exception as e:
            fetch_mail_logger.warning(
                f"Error creating analyzer '{analyzer.name}': {str(e)}"
            )

        # Fallback: find existing Analyzer by name
        analyzer_db = Analyzer.objects.filter(name=analyzer.name).first()
        if analyzer_db:
            # Update second Cortex ID if needed
            if analyzer_db.analyzer_cortex_2_id != analyzer.id:
                analyzer_db.analyzer_cortex_2_id = analyzer.id
                analyzer_db.save(update_fields=["analyzer_cortex_2_id"])

        return analyzer_db

    @staticmethod
    def set_analyzer_report_data(analyzer_report, data, data_type):
        """
        Set the relevant fields of an AnalyzerReport object based on its data type.

        Args:
            analyzer_report (AnalyzerReport): The report object to update.
            data: The data to assign (file, URL, IP, hash, MailBody, MailHeader, etc.).
            data_type (str): Type of the data ('file', 'url', 'ip', 'domain', 'mail', 'hash', 'mail_body', 'mail_header').

        Raises:
            ValueError: If an unsupported data_type is provided.
        """
        if not isinstance(analyzer_report, AnalyzerReport):
            raise TypeError("analyzer_report must be an instance of AnalyzerReport")

        if data_type in {"file", "url", "ip", "domain", "mail", "hash"}:
            setattr(analyzer_report, data_type, data)

        elif data_type == "mail_body":
            if not isinstance(data, str):
                raise TypeError("data must be a string for mail_body")
            fuzzy = data.split("/")[-1].split(".")[0]
            mail_body, _ = MailBody.objects.get_or_create(
                fuzzy_hash=fuzzy, defaults={"body_value": data}
            )
            analyzer_report.mail_body = mail_body

        elif data_type == "mail_header":
            if not isinstance(data, MailHeader):
                raise TypeError("data must be a MailHeader instance for mail_header")
            analyzer_report.mail_header = data

        else:
            raise ValueError(f"Unsupported data type: {data_type}")

        # Save properly
        if analyzer_report.pk:
            analyzer_report.save(update_fields=[data_type])
        else:
            analyzer_report.save()

class CortexJobManager:
    _job_cache = {}  # Cache for Cortex jobs to avoid repeated API calls
    _report_cache = {}  # Cache for Cortex reports to avoid repeated API calls

    def __init__(self):
        self.case = None
        self.last_processed = {}  # Track last processed report IDs per data_type

        # Define the structure for results with sets for unique report IDs per data type and status
        categories = [
            "ip",
            "domain",
            "mail",
            "url",
            "hash",
            "file",
            "mail_body",
            "mail_header",
            "total",
        ]

        self.results = {
            cat: {
                "reports": set(),
                "success": set(),
                "inprogress": set(),
                "failure": set(),
                "waiting": set(),
                "deleted": set(),
            }
            for cat in categories
        }

        # API configuration
        self.api_urls = API_URL
        self.api_keys = API_KEY

    @classmethod
    def get_cortex_jobs_results(cls, report_instance, data_type):
        """
        Get the status of a Cortex job for a report instance, update report fields efficiently.

        Args:
            report_instance (AnalyzerReport): The report object
            data_type (str): One of 'file', 'url', 'ip', 'hash', 'domain', 'mail', 'mail_header', 'mail_body'

        Returns:
            str: Updated status of the report
        """
        if not isinstance(report_instance, AnalyzerReport):
            raise TypeError("report_instance must be an AnalyzerReport instance")
        if data_type not in [
            "file",
            "url",
            "ip",
            "hash",
            "domain",
            "mail",
            "mail_header",
            "mail_body",
        ]:
            raise ValueError(f"Invalid data_type: {data_type}")

        job_id = report_instance.cortex_job_id

        # Fetch job using cache
        job = cls._job_cache.get(job_id)
        if job is None:
            job = cls.get_job_from_api(job_id)
            cls._job_cache[job_id] = job

        if job == "old_job":
            if report_instance.status != "Deleted":
                report_instance.status = "Deleted"
                report_instance.save(update_fields=["status"])
            return report_instance.status

        if job and (
            job.dataType == data_type
            or (data_type == "mail_body" and job.dataType == "file")
        ):
            # Fetch report using cache
            report = cls._report_cache.get(job_id)
            if report is None:
                report = cls.get_report_from_api(job_id)
                cls._report_cache[job_id] = report

            if report:
                try:
                    updated_fields = cls.update_report_instance(
                        report_instance, job, report
                    )
                    if updated_fields:
                        report_instance.save(update_fields=updated_fields)
                except Exception as e:
                    update_cases_logger.error(
                        f"Error updating report {job_id}: {e}", exc_info=True
                    )

        return report_instance.status

    @staticmethod
    def get_job_from_api(job_id):
        apis = [API]  # extendable list of APIs
        for api in apis:
            try:
                job = api.jobs.get_by_id(job_id)
                if job:
                    return job
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching job {job_id}: {e}", exc_info=True
                )
        return "old_job"  # return "old_job" only if not found in any API

    @staticmethod
    def get_report_from_api(job_id):
        apis = [API]
        for api in apis:
            try:
                report = api.jobs.get_report(job_id)
                if report:
                    return getattr(report, "report", None)
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching report for job {job_id}: {e}", exc_info=True
                )
        return None

    @staticmethod
    def update_report_instance(report_instance, job, report):
        """
        Update report_instance fields efficiently, return list of changed fields.
        """
        if not all([report_instance, job, report]):
            raise ValueError("report_instance, job, and report cannot be None")
        if not hasattr(job, "status"):
            raise AttributeError("job object has no attribute 'status'")

        updated_fields = []

        # Update status
        if report_instance.status != job.status:
            report_instance.status = job.status
            updated_fields.append("status")

        # Update report fields if job succeeded
        if job.status == "Success" and isinstance(report, dict):
            summary = report.get("summary")
            if summary and summary != getattr(report_instance, "report_summary", None):
                report_instance.report_summary = summary
                updated_fields.append("report_summary")

            taxonomies = summary.get("taxonomies") if summary else None
            if taxonomies and taxonomies != getattr(
                report_instance, "report_taxonomy", None
            ):
                report_instance.report_taxonomy = taxonomies
                updated_fields.append("report_taxonomy")

            full = report.get("full")
            if full and full != getattr(report_instance, "report_full", None):
                report_instance.report_full = full
                updated_fields.append("report_full")

        return updated_fields

    def get_results(self, case):
        """
        Process the case and get the results, efficiently handling large numbers of reports.

        Args:
            case (Case): An instance of the Case model.

        Returns:
            dict: The aggregated results of the Cortex jobs.
        """
        if not case:
            raise ValueError("Case is required.")

        # Set current case for last_processed tracking
        self.case = case

        # Process file and/or mail
        file_or_mail = getattr(case, "fileOrMail", None)
        if file_or_mail:
            if getattr(file_or_mail, "file", None):
                self.process_file(file=file_or_mail.file)
            if getattr(file_or_mail, "mail", None):
                self.process_mail(mail=file_or_mail.mail)

        # Process non-file IOCs
        iocs = getattr(case.nonFileIocs, "get_iocs", lambda: None)()
        if iocs:
            self.process_iocs(iocs=iocs)
        elif getattr(case, "nonFileIocs", None):
            # Case has nonFileIocs object but no IOCs inside
            raise ValueError("IOCs are required.")

        # Aggregate all unique results
        self.calculate_total_results()

        update_cases_logger.debug(f"Results for case {case.id}: {self.results}")
        return self.results

    def get_new_reports(self, data_type, filter_kwargs):
        """
        Fetch only new AnalyzerReport objects since last_processed checkpoint
        for this case and data_type.
        """
        key = (self.case.id, data_type)  # unique tracker per case/type
        last_seen = self.last_processed.get(key, datetime.now() - timedelta(days=1))

        reports = AnalyzerReport.objects.filter(
            type=data_type, creation_date__gt=last_seen, **filter_kwargs
        )

        # Move the checkpoint forward
        self.last_processed[key] = datetime.now()
        return reports

    def process_file(self, file):
        """
        Process a file and update the results based on related reports.

        Args:
            file: The file to be processed.

        Raises:
            ValueError: If the file is None.
        """
        if not file:
            raise ValueError("File cannot be None")

        # --- File reports ---
        reports_file = self.get_new_reports(
            data_type="file", filter_kwargs={"file": file}
        )
        if reports_file.exists():
            self.update_results(data_type="file", reports=list(reports_file))

        # --- Linked hash reports ---
        if file.linked_hash:
            reports_file_hash = self.get_new_reports(
                data_type="hash", filter_kwargs={"hash": file.linked_hash}
            )
            if reports_file_hash.exists():
                self.update_results(data_type="hash", reports=list(reports_file_hash))

    def process_mail(self, mail):
        """
        Process the given mail object.

        Args:
            mail: The mail object to be processed.

        Raises:
            ValueError: If the mail object is None.
        """
        if not mail:
            raise ValueError("Mail object cannot be None")

        # --- Process mail artifacts ---
        mail_artifacts = mail.mail_artifacts.all()
        if mail_artifacts:
            self.process_artifacts(artifacts=mail_artifacts)
        else:
            update_cases_logger.info(f"No mail artifacts found for mail {mail.id}")

        # --- Process mail archive ---
        try:
            mail_archive = MailArchive.objects.filter(mail=mail).first()
        except Exception:
            mail_archive = None
            update_cases_logger.info(f"No archive file found for mail {mail.id}")

        if mail_archive:
            self.process_mail_archive(mail_archive.archive)

        # --- Process mail attachments ---
        mail_attachments = mail.mail_attachments.all()
        if mail_attachments:
            self.process_attachments(attachments=mail_attachments)
        else:
            update_cases_logger.info(f"No mail attachments found for mail {mail.id}")

        # --- Process mail body ---
        mail_body = mail.mail_body
        if mail_body:
            reports = self.get_new_reports(
                data_type="mail_body", filter_kwargs={"mail_body": mail_body}
            )
            if reports.exists():
                self.update_results(data_type="mail_body", reports=reports)
            else:
                update_cases_logger.info(
                    f"No new reports found for mail body of mail {mail.id}"
                )
        else:
            update_cases_logger.info(f"No mail body found for mail {mail.id}")

        # --- Process mail headers ---
        mail_headers = mail.mail_header
        if mail_headers:
            reports = self.get_new_reports(
                data_type="mail_header", filter_kwargs={"mail_header": mail_headers}
            )
            if reports.exists():
                self.update_results(data_type="mail_header", reports=reports)
            else:
                update_cases_logger.info(
                    f"No new reports found for mail headers of mail {mail.id}"
                )
        else:
            update_cases_logger.info(f"No mail headers found for mail {mail.id}")

    def process_mail_archive(self, mail_archive):
        """
        Process a mail archive.

        Args:
            mail_archive: The mail archive file to be processed.

        Raises:
            ValueError: If mail_archive is None.
        """
        if not mail_archive:
            raise ValueError("MailArchive cannot be None")

        reports_file = self.get_new_reports(
            data_type="file", filter_kwargs={"file": mail_archive}
        )

        if reports_file.exists():
            self.update_results(data_type="file", reports=list(reports_file))
        else:
            update_cases_logger.info(
                f"No new reports found for mail archive {mail_archive}"
            )

    def process_artifacts(self, artifacts):
        """
        Process a list of artifacts using their corresponding processor methods.

        Args:
            artifacts (list): A list of artifacts to be processed.

        Returns:
            None
        """
        artifact_processing_methods = {
            "IP": self.process_ip_artifact,
            "URL": self.process_url_artifact,
            "Hash": self.process_hash_artifact,
            "Domain": self.process_domain_artifact,
            "MailAddress": self.process_mail_artifact,
        }

        for artifact in artifacts:
            if not artifact:
                continue
            try:
                processing_method = artifact_processing_methods.get(
                    artifact.artifact_type
                )
                if processing_method:
                    processing_method(artifact)
                else:
                    update_cases_logger.info(
                        f"No processor for artifact type: {artifact.artifact_type}"
                    )
            except Exception as e:
                update_cases_logger.error(
                    f"Error processing artifact {artifact}: {str(e)}"
                )
                logging.error(f"Error processing artifact {artifact}: {str(e)}")

    def process_ip_artifact(self, artifact):
        if not artifact.artifactIsIp:
            raise ValueError("The provided artifact is not an IP.")

        reports = self.get_new_reports("ip", {"ip": artifact.artifactIsIp.ip})

        if reports.exists():
            self.update_results(data_type="ip", reports=reports)
        else:
            update_cases_logger.info("No new reports found related to IP.")

    def process_url_artifact(self, artifact):
        """
        Process a URL artifact.

        Args:
            artifact: The URL artifact to process.

        Returns:
            None
        """
        # Validate artifact type
        if not artifact.artifactIsUrl:
            raise ValueError("The provided artifact is not a URL")

        reports = self.get_new_reports(
            data_type="url",
            filter_kwargs={"url": artifact.artifactIsUrl.url},
        )

        if not reports.exists():
            update_cases_logger.info(
                f"No new reports found for the provided URL: {artifact.artifactIsUrl.url}"
            )
            return

        self.update_results(data_type="url", reports=reports)

    def process_hash_artifact(self, artifact):
        """
        Process a Hash artifact.

        Args:
            artifact: The Hash artifact to process.

        Returns:
            None
        """
        # Validate artifact type
        if not artifact.artifactIsHash:
            raise ValueError("The provided artifact is not a Hash")

        reports = self.get_new_reports(
            data_type="hash",
            filter_kwargs={"hash": artifact.artifactIsHash.hash},
        )

        if not reports.exists():
            update_cases_logger.info(
                f"No new reports found for the provided Hash: {artifact.artifactIsHash.hash}"
            )
            return

        self.update_results(data_type="hash", reports=reports)

    def process_domain_artifact(self, artifact):
        """
        Process a Domain artifact.

        Args:
            artifact: The Domain artifact to process.

        Returns:
            None
        """
        # Validate artifact type
        if not artifact.artifactIsDomain:
            raise ValueError("The provided artifact is not a Domain")

        reports = self.get_new_reports(
            data_type="domain",
            filter_kwargs={"domain": artifact.artifactIsDomain.domain},
        )

        if not reports.exists():
            update_cases_logger.info(
                f"No new reports found for the provided Domain: {artifact.artifactIsDomain.domain}"
            )
            return

        self.update_results(data_type="domain", reports=reports)

    def process_mail_artifact(self, artifact):
        """
        Process a Mail artifact.

        Args:
            artifact: The Mail artifact to process.

        Returns:
            None
        """
        # Validate artifact type
        if not artifact.artifactIsMailAddress:
            raise ValueError("The provided artifact is not a Mail")

        reports = self.get_new_reports(
            data_type="mail",
            filter_kwargs={"mail": artifact.artifactIsMailAddress.mail_address},
        )

        if not reports.exists():
            update_cases_logger.info(
                f"No new reports found related to the provided Mail Address: {artifact.artifactIsMailAddress.mail_address}"
            )
            return

        self.update_results(data_type="mail", reports=reports)

    def process_attachments(self, attachments):
        """
        Process a list of attachments.

        Args:
            attachments (list): A list of attachments to be processed.

        Returns:
            None
        """
        if not attachments:
            update_cases_logger.info("No attachments to process.")
            return

        for attachment in attachments:
            if not attachment.file:
                update_cases_logger.info(
                    f"No file found in attachment {attachment}. Skipping."
                )
                continue

            try:
                # process_file already handles deduplication + get_new_reports
                self.process_file(file=attachment.file)
            except Exception as e:
                update_cases_logger.error(
                    f"Error processing file in attachment {attachment}: {e}"
                )

    def process_iocs(self, iocs):
        """
        Process a dictionary of Indicators of Compromise (IOCs).

        Args:
            iocs (dict): A dictionary of IOCs to be processed.
                        Keys: type of IOC (url, ip, hash, domain, mail)
                        Values: the actual IOC values.

        Returns:
            None
        """
        ioc_type_to_filter_param = {
            "url": "url",
            "ip": "ip",
            "hash": "hash",
            "domain": "domain",
            "mail": "mail",
        }

        for ioc_type, ioc_value in iocs.items():
            # Skip unsupported IOC types
            if ioc_type not in ioc_type_to_filter_param:
                update_cases_logger.info(f"Unsupported IOC type: {ioc_type}")
                continue

            filter_param = ioc_type_to_filter_param[ioc_type]

            reports = self.get_new_reports(
                data_type=ioc_type,
                filter_kwargs={filter_param: ioc_value},
            )

            if not reports.exists():
                update_cases_logger.info(
                    f"No new reports found for {ioc_type}: {ioc_value}"
                )
                continue

            self.update_results(data_type=ioc_type, reports=reports)

    def clean_id(self, report_id):
        """
        Normalize a report ID so duplicates and invalid values are removed.
        Adjust this to match your DB schema (UUID, int, etc.).
        """
        if report_id is None:
            return None
        # normalize to string (safe for UUIDs, ints, etc.)
        rid = str(report_id).strip()
        if not rid:
            return None
        return rid

    def update_results(self, data_type, reports):
        """
        Update the results of the Cortex jobs with the given data type and reports.

        Deduplicates and cleans report IDs before inserting them.
        """
        try:
            for report in reports:
                report_id = self.clean_id(report.id)
                if not report_id:
                    continue

                # Skip if already processed
                if report_id in self.results[data_type]["reports"]:
                    continue

                # Mark report as seen
                self.results[data_type]["reports"].add(report_id)

                # Get the job result
                status = self.get_cortex_jobs_results(report, data_type)
                if status and status.lower() in {
                    "success",
                    "failure",
                    "waiting",
                    "inprogress",
                    "deleted",
                }:
                    self.results[data_type][status.lower()].add(report_id)

        except Exception as e:
            update_cases_logger.error(f"Error updating results: {e}")
            logging.error(
                f"Error getting Cortex {data_type} jobs results for case {e}",
                exc_info=True,
            )

    def calculate_total_results(self):
        """
        Recompute totals from scratch to avoid inflated counts.
        """
        # Always reset before aggregation
        total_reports = set()
        total_success = set()
        total_inprogress = set()
        total_failure = set()
        total_waiting = set()
        total_deleted = set()

        for category_name, category in self.results.items():
            if not isinstance(category, dict):
                continue
            if all(
                key in category
                for key in ["reports", "success", "inprogress", "failure", "waiting", "deleted"]
            ):
                total_reports.update(map(self.clean_id, category["reports"]))
                total_success.update(map(self.clean_id, category["success"]))
                total_inprogress.update(map(self.clean_id, category["inprogress"]))
                total_failure.update(map(self.clean_id, category["failure"]))
                total_waiting.update(map(self.clean_id, category["waiting"]))
                total_deleted.update(map(self.clean_id, category["deleted"]))

        # Drop None if cleaning failed
        total_reports.discard(None)
        total_success.discard(None)
        total_inprogress.discard(None)
        total_failure.discard(None)
        total_waiting.discard(None)
        total_deleted.discard(None)

        self.results["total"] = {
            "reports": total_reports,
            "success": total_success,
            "inprogress": total_inprogress,
            "failure": total_failure,
            "waiting": total_waiting,
            "deleted": total_deleted,
        }

    def generate_description(self, case):
        """
        Generates a user-friendly description for the case based on the current job execution results.

        Args:
            case (Case): The case object to update.

        Returns:
            None
        """
        total_reports = self.results["total"]["reports"]
        success = self.results["total"]["success"]
        failure = self.results["total"]["failure"]
        waiting = self.results["total"]["waiting"]
        ongoing = self.results["total"]["inprogress"]
        deleted = self.results["total"]["deleted"]

        total_job = len(total_reports)
        success_count = len(success)
        failure_count = len(failure)
        waiting_count = len(waiting)
        ongoing_count = len(ongoing)
        deleted_count = len(deleted)

        update_cases_logger.info(
            f"Total jobs: {total_job}, Success: {success_count}, Failure: {failure_count}, "
            f"Waiting: {waiting_count}, Ongoing: {ongoing_count}, Deleted: {deleted_count}"
        )

        adjusted_total = total_job - deleted_count if total_job else 0
        success_ratio = success_count / adjusted_total if adjusted_total else 0
        failure_ratio = failure_count / adjusted_total if adjusted_total else 0

        all_done = total_reports == (success | failure | deleted)
        all_finished = all_done and (ongoing_count == 0 and waiting_count == 0)

        if all_finished:
            case.status = "Done"
            if failure_count == 0:
                case.description = "All analyzers completed successfully. You can now view the full results."
            elif success_count == 0:
                case.description = "All analyzers failed to run. Please check the configuration and retry."
            elif success_ratio > 0.6:
                case.description = (
                    f"Most analyzers ({success_count}/{adjusted_total}) succeeded. "
                    "Consider rerunning remaining analyzers for a complete analysis."
                )
            elif failure_ratio > 0.6:
                case.description = (
                    f"Most analyzers ({failure_count}/{adjusted_total}) failed. "
                    "This case is marked as done, but please check for potential issues with the analyzers or network."
                )
            else:  # roughly 40%-60% success
                case.description = (
                    f"About half of the analyzers succeeded ({success_count}/{adjusted_total}). "
                    "Some results are available, consider rerunning others for a more complete analysis."
                )
        else:
            case.status = "On Going"
            if ongoing_count > 0:
                case.description = (
                    f"{ongoing_count} out of {total_job} analyzers are still running. "
                    "Results will be updated once finished."
                )
            else:
                completed = success_count + failure_count
                case.description = (
                    f"{completed} out of {total_job} analyzers have finished. "
                    "Some analyzers may still be processing."
                )

        case.save()

    def manage_jobs(self, case):
        """
        Manage and update Cortex jobs for a given case, with user-friendly results and descriptions.

        Steps:
        1. Fetch results for the case (files, mail, IOCs, attachments, artifacts).
        2. Generate a user-friendly description and update case status.
        3. Retrieve final report if the case is complete.

        Args:
            case (Case): The case to process.

        Returns:
            None
        """
        if not case:
            raise ValueError("Case is required.")

        # Fetch and process all relevant results for this case
        results = self.get_results(case)

        # If no results were generated, exit early
        if not results or not results.get("total"):
            update_cases_logger.info(f"No results found for case {case.id}")
            return

        # Generate a user-friendly description and update status
        self.generate_description(case)

        # If all jobs are done, fetch the final report
        if case.status == "Done":
            try:
                CortexAnalyzerReports.get_report(case)
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching final report for case {case.id}: {e}",
                    exc_info=True,
                )

        # Save the updated case object
        case.save()

    def manage_ai_jobs(self, case):
        """
        Manage AI jobs for a case.

        Updates the case and MailInfo models if AI analysis has completed.

        Args:
            case (Case): The case to manage.
        """
        if case.status != "Done":
            update_cases_logger.info(
                "Case status is not 'Done'. Skipping AI job management."
            )
            return

        # Validate presence of mail
        try:
            eml = getattr(case.fileOrMail, "mail", None)
            if not eml or not getattr(eml, "mail_id", None):
                update_cases_logger.info("No valid mail found for case %s", case.id)
                return
        except Exception as e:
            update_cases_logger.error(
                "Error retrieving mail for case %s: %s", case.id, e
            )
            return

        # Get mail archive
        try:
            mail_archive = MailArchive.objects.filter(mail=eml).first()
            if not mail_archive:
                update_cases_logger.info("No archive file found for case %s", case.id)
                return
        except Exception as e:
            update_cases_logger.error(
                "Error retrieving MailArchive for case %s: %s", case.id, e
            )
            return

        update_cases_logger.info("Processing archive file: %s", mail_archive)

        # Get AI analyzer report
        try:
            analyzer = AnalyzerReport.objects.get(
                analyzer__name=cortex_config.get("ai_analyzer"),
                file=mail_archive.archive,
            )
            update_cases_logger.info("AI Mail Analyzer report found: %s", analyzer)
        except AnalyzerReport.DoesNotExist:
            update_cases_logger.info(
                "No AI Mail Analyzer report found for archive file: %s",
                mail_archive.archive,
            )
            return
        except Exception as e:
            update_cases_logger.error("Error retrieving analyzer report: %s", e)
            return

        # Update case with AI analysis
        try:
            case.scoreAI = analyzer.score
            case.confidenceAI = analyzer.confidence * 10
            case.categoryAI = self.get_sub_class(analyzer)
            case.resultsAI = analyzer.level.capitalize()
            case.save()

            update_cases_logger.info(
                "AI Mail Analyzer updated for case %s: score=%f, confidence=%f, category=%s",
                case.id,
                case.scoreAI,
                case.confidenceAI,
                case.categoryAI,
            )

            # Update associated MailInfo
            mail_info = MailInfo.objects.get(mail=eml)
            self.update_mail_models(mail_info, case.categoryAI, case.resultsAI)

        except Exception as e:
            update_cases_logger.exception("Error updating case or mail info: %s", e)

    def update_mail_models(self, mail_info, classification, sub_classification):
        """
        Update MailInfo model based on classification results.

        Args:
            mail_info (MailInfo): The mail info object to update.
            classification (str): The main classification of the mail.
            sub_classification (str): The subclassification of the mail.
        """
        if not mail_info:
            update_cases_logger.warning("No MailInfo provided to update")
            return

        try:
            mail_info.is_analyzed = True

            # Normalize strings to lowercase for safe comparison
            classification_lower = (classification or "").strip().lower()
            sub_class_lower = (sub_classification or "").strip().lower()

            # Set phishing flag
            if classification_lower in {"classic_phishing", "whaling", "clone"}:
                mail_info.is_phishing = True

            # Set dangerous flag
            if sub_class_lower == "dangerous":
                mail_info.is_dangerous = True

            mail_info.save()
            update_cases_logger.info(
                f"MailInfo updated for Mail ID: {getattr(mail_info.mail, 'id', 'Unknown')}"
            )

        except Exception as e:
            update_cases_logger.error(f"Error updating MailInfo/MailAnalyzed: {e}")

    def get_sub_class(self, analyzer):
        """
        Get the subclass of the analyzer report.

        Args:
            analyzer (AnalyzerReport): The analyzer report object.

        Returns:
            str: The subclass of the analyzer, capitalized, or a default message if not found.
        """
        default_message = "No subclass found"

        if not analyzer:
            return default_message

        report_full = getattr(analyzer, "report_full", None)
        if not report_full:
            return default_message

        # Ensure report_full is a dictionary
        if isinstance(report_full, str):
            try:
                report_full = json.loads(report_full)
            except json.JSONDecodeError:
                update_cases_logger.warning("Failed to parse report_full as JSON")
                return default_message

        subclass = report_full.get("sub_classification")
        if subclass:
            return str(subclass).capitalize()

        return default_message
