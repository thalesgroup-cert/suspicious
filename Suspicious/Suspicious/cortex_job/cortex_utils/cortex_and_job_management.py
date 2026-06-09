import logging

import pybreaker
from django.db import transaction
from django.utils import timezone

from common.http_client import get_breaker, RETRY
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
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
try:
    from settings.config import get_section as _get_section
    cortex_config = _get_section("integrations.cortex")
except Exception as _cfg_err:
    fetch_mail_logger.error(f"Could not load cortex config: {_cfg_err}")
    cortex_config = {}

# ------------------------
# API settings
# ------------------------
API_URL = cortex_config.get("url", "https://cortex.example.com")
API_KEY = cortex_config.get("api_key", "your_api_key_here")

# Reports stuck in Waiting/InProgress beyond this many seconds are
# auto-failed so the parent case can finish. 24h matches the worst-case
# Cortex analyzer (sandbox detonation) we have observed.
STALE_JOB_TIMEOUT_SECONDS: int = int(
    cortex_config.get("stale_job_timeout_seconds", 86400)
)

try:
    API = SessionCortexApi(API_URL, API_KEY, proxies={"http": "", "https": ""})
except Exception as e:
    fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
    API = None

_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_job(api, job_id: str):
    """Fetch a Cortex job by ID with retry and circuit breaker."""
    with _cortex_breaker.calling():
        return api.jobs.get_by_id(job_id)


@RETRY
def _fetch_report(api, job_id: str):
    """Fetch a Cortex job report by ID with retry and circuit breaker."""
    with _cortex_breaker.calling():
        return api.jobs.get_report(job_id)


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
            self.api = SessionCortexApi(self.api_url, self.api_key, proxies=self.proxies)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
            self.api = None

    def launch_cortex_jobs(self, value, data_type, case):
        """
        Launch Cortex jobs for the given value and data type.

        Args:
            value: The object to be analyzed (file, mail, domain, etc.).
            data_type (str): The type of data ('file', 'url', 'mail_body', etc.).
            case (Case): The case the dispatched jobs belong to.

        Returns:
            list[str]: A list of job IDs for the launched Cortex jobs.
        """
        api_launchjob = self.api
        analyzers = []

        try:
            # --- FILE and MAIL_BODY special handling ---
            if data_type in ["file", "mail_body"]:
                if data_type == "mail_body":
                    yara_name = (cortex_config.get("analyzers").get("yara"))
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
                            (cortex_config.get("analyzers", {}).get("ai", {})),
                            (cortex_config.get("analyzers", {}).get("yara", {})),
                            (cortex_config.get("analyzers", {}).get("sandbox", {})),
                            (cortex_config.get("analyzers", {}).get("header", {})),
                        }
                        analyzers = [
                            a for a in analyzers if a and a.name not in excluded
                        ]

            # --- MAIL_HEADER handling ---
            elif data_type == "mail_header":
                header_name = (cortex_config.get("analyzers", {}).get("header", {}))
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
                    report = CortexJob.run(api_launchjob, analyzer, value, data_type, case)
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

    def launch_cortex_ai_jobs(self, value, data_type, case):
        """
        Launch Cortex AI jobs for the given value and data type.

        Args:
            value: The object to analyze (file, archive, etc.).
            data_type (str): The type of data ('file', 'mail_body', etc.).
            case (Case): The case the dispatched jobs belong to.

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
            ai_analyzer_name = (cortex_config.get("analyzers", {}).get("ai", {}))
            analyzer = self.api.analyzers.get_by_name(ai_analyzer_name)
            if not analyzer:
                fetch_mail_logger.warning(f"AI analyzer '{ai_analyzer_name}' not found")
                return None

            # Run analyzer using CortexJob.run
            report = CortexJob.run(self.api, analyzer, archive, "file", case)
            return getattr(report, "id", None)
        except Exception as e:
            fetch_mail_logger.error(f"Error launching Cortex AI job: {e}")
            return None

    @staticmethod
    def run(api, analyzer, value, data_type, case):
        """
        Run an analyzer on the provided value using the Cortex API.

        Args:
            api: Cortex API object.
            analyzer: Analyzer object.
            value: Data to analyze.
            data_type (str): Type of the data ('file', 'mail_body', 'url', 'ip', 'hash', etc.)
            case (Case): The case the analyzer is being run for.

        Returns:
            The Cortex job report object if successful, None otherwise.
        """
        if data_type == "mail_body":
            return CortexJob.run_analyzer(api, analyzer, value, "mail_body", case)
        return CortexJob.run_analyzer(api, analyzer, value, data_type, case)

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
                (cortex_config.get("analyzers", {}).get("yara", {})),
                (cortex_config.get("analyzers", {}).get("file_info", {})),
                (cortex_config.get("analyzers", {}).get("sandbox", {})),
            ],
        )

        analyzers = []

        for analyzer_name in analyzer_names:
            # Skip Yara analyzer for .eml files
            if analyzer_name == (cortex_config.get("analyzers", {}).get("yara", {})) and file.file_path.name.endswith(".eml"):
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
                    (cortex_config.get("analyzers", {}).get("yara", {})),
                    (cortex_config.get("analyzers", {}).get("sandbox", {})),
                    (cortex_config.get("analyzers", {}).get("header", {})),
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
    @transaction.atomic
    def run_analyzer(api, analyzer, data, data_type, case):
        """
        Run a Cortex analyzer on the given data; record AnalyzerReport +
        CaseAnalyzerJob atomically.

        The whole function runs inside a transaction so a CaseAnalyzerJob
        failure rolls back the AnalyzerReport row.
        """
        if case is None:
            raise TypeError("run_analyzer requires a non-None case")

        try:
            data_value = CortexJob.get_data_value(data, data_type)
        except Exception as e:
            fetch_mail_logger.error(f"Error extracting data value for {data_type}: {e}")
            return None

        if not data_value or (isinstance(data_value, str) and not data_value.strip()):
            fetch_mail_logger.debug(
                f"Skip analyzer '{analyzer.name}' on {data_type}: empty data value"
            )
            return None

        payload = {
            "data": data_value,
            "dataType": "file" if data_type == "mail_body" else data_type,
            "tlp": 2,
        }

        try:
            report = api.analyzers.run_by_name(analyzer.name, payload)
        except Exception as e:
            fetch_mail_logger.warning(
                f"Analyzer '{analyzer.name}' rejected {data_type} input: {e}"
            )
            return None

        analyzer_db = CortexJob.get_analyzer_db(analyzer)

        if report:
            fetch_mail_logger.debug(
                f"Analyzer '{analyzer.name}' run successfully for data type '{data_type}'"
            )

            analyzer_report = AnalyzerReport(
                cortex_job_id=report.id,
                type=data_type,
                analyzer=analyzer_db,
                status="InProgress",
                level="info",
                confidence=0,
                score=0,
                report_summary={"ongoing": "analysis"},
                report_full={"ongoing": "analysis"},
                report_taxonomy={"ongoing": "analysis"},
            )

            # set_analyzer_report_data saves analyzer_report internally
            # (see set_analyzer_report_data body). Let any exception
            # propagate so the outer transaction.atomic rolls back the
            # report row alongside the CaseAnalyzerJob that we are about
            # to create. The previous try/except here silently swallowed
            # save errors and is removed.
            CortexJob.set_analyzer_report_data(analyzer_report, data, data_type)

            CaseAnalyzerJob.objects.create(
                case=case,
                cortex_job_id=report.id,
                analyzer=analyzer_db,
                analyzer_report=analyzer_report,
                status=CaseAnalyzerJob.STATUS_INPROGRESS,
            )

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
            Analyzer: The retrieved or newly created Analyzer instance, or None if
            creation failed and no row could be located by name.
        """
        if not hasattr(analyzer, "id") or not hasattr(analyzer, "name"):
            raise TypeError("analyzer must have 'id' and 'name' attributes")

        try:
            return Analyzer.objects.get(analyzer_cortex_id=analyzer.id)
        except Analyzer.DoesNotExist:
            pass

        # Wrap create in a nested savepoint so an IntegrityError from a concurrent
        # dispatch race does not poison the surrounding transaction.atomic block
        # (run_analyzer wraps this call in atomic).
        try:
            with transaction.atomic():
                return Analyzer.objects.create(
                    analyzer_cortex_id=analyzer.id,
                    name=analyzer.name,
                    weight=0.2,
                )
        except Exception as e:
            fetch_mail_logger.warning(
                f"Error creating analyzer '{analyzer.name}': {str(e)}"
            )

        # Fallback: another worker created the row first — return it.
        return Analyzer.objects.filter(name=analyzer.name).first()

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

    @staticmethod
    def _artifact_value(report_instance):
        """Return the scoring value for the artifact linked to this report."""
        if report_instance.url_id:
            return report_instance.url.address
        if report_instance.ip_id:
            return report_instance.ip.address
        if report_instance.mail_id:
            return report_instance.mail.address
        if report_instance.domain_id:
            return report_instance.domain.value
        if report_instance.hash_id:
            return report_instance.hash.value
        if report_instance.file_id:
            return str(report_instance.file.file_path.name)
        if report_instance.mail_body_id:
            return report_instance.mail_body.fuzzy_hash
        if report_instance.mail_header_id:
            return report_instance.mail_header.fuzzy_hash
        raise ValueError(
            f"AnalyzerReport {report_instance.pk} has no linked artifact"
        )

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

            # Score immediately on success so the UI does not wait for the
            # case to flip to Done. create_and_save_report is idempotent.
            if job.status == "Success":
                try:
                    from score_process.scoring.cortex_analyzers.reports import (
                        CortexAnalyzerReports,
                    )
                    artifact_value = cls._artifact_value(report_instance)
                    CortexAnalyzerReports.create_and_save_report(
                        report_instance, artifact_value, None
                    )
                except Exception as e:
                    update_cases_logger.error(
                        f"Error scoring report {job_id}: {e}", exc_info=True
                    )

        # Age anchored to CaseAnalyzerJob.created_at (dispatch time), not
        # AnalyzerReport.creation_date — that can drift on Deleted/resurrected
        # rewrites or queue lag.
        if report_instance.status in {"Waiting", "InProgress"}:
            submitted_at = (
                CaseAnalyzerJob.objects
                .filter(cortex_job_id=job_id)
                .order_by("created_at")
                .values_list("created_at", flat=True)
                .first()
            ) or report_instance.creation_date
            if submitted_at is not None:
                age = (timezone.now() - submitted_at).total_seconds()
                if age > STALE_JOB_TIMEOUT_SECONDS:
                    update_cases_logger.warning(
                        "Auto-failing stale %s report cortex_job_id=%s after %.0fs",
                        report_instance.status, job_id, age,
                    )
                    report_instance.status = "Failure"
                    report_instance.save(update_fields=["status"])

        return report_instance.status

    @staticmethod
    def get_job_from_api(job_id):
        for api in [API]:
            if api is None:
                continue
            try:
                job = _fetch_job(api, job_id)
                if job:
                    return job
            except pybreaker.CircuitBreakerError as e:
                update_cases_logger.warning(
                    "[breaker:cortex] open — get_job_from_api skipped for job %s: %s", job_id, e
                )
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching job {job_id}: {e}", exc_info=True
                )
        return "old_job"

    @staticmethod
    def get_report_from_api(job_id):
        for api in [API]:
            if api is None:
                continue
            try:
                report = _fetch_report(api, job_id)
                if report:
                    return getattr(report, "report", None)
            except pybreaker.CircuitBreakerError as e:
                update_cases_logger.warning(
                    "[breaker:cortex] open — get_report_from_api skipped for job %s: %s", job_id, e
                )
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

        # Set current case for downstream processing
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
        Fetch all non-Deleted AnalyzerReport objects for this data_type
        and artifact filter. Cortex API calls are deduplicated via the
        class-level _job_cache / _report_cache during a single tick.
        """
        return AnalyzerReport.objects.filter(
            type=data_type, **filter_kwargs
        ).exclude(status="Deleted")

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

        if mail_archive and mail_archive.archive:
            self.process_mail_archive(mail_archive.archive)
        elif mail_archive:
            update_cases_logger.info(
                f"MailArchive {mail_archive.id} for mail {mail.id} has no archive file"
            )

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

        all_done = bool(total_reports) and total_reports == (success | failure | deleted)
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

    def update_single_job(self, caj) -> None:
        """Sync a single CaseAnalyzerJob + its AnalyzerReport from Cortex.

        Mirrors the per-report logic from get_cortex_jobs_results but scoped
        to a single (case, cortex_job_id) pair. The CaseAnalyzerJob status
        is updated to match the AnalyzerReport status returned by Cortex.
        Completed_at is set when the job leaves the pending states.
        """
        from cortex_job.models import CaseAnalyzerJob
        report = caj.analyzer_report
        if report is None:
            return
        data_type = report.type
        new_status = self.get_cortex_jobs_results(report, data_type)

        if new_status and new_status != caj.status:
            caj.status = new_status
            if new_status not in CaseAnalyzerJob.PENDING_STATUSES:
                caj.completed_at = timezone.now()
            caj.save(update_fields=["status", "completed_at"])

    def finalise_case(self, case) -> None:
        """Compute final description + status + trigger CortexAnalyzerReports.

        Called once when the case's CaseAnalyzerJob pending-count drops to 0.
        Mirrors the tail end of manage_jobs but without the per-case bulk
        aggregation step that manage_jobs performs.

        CortexAnalyzerReports.get_report is safe to call multiple times for
        most of its work (create_and_save_report overwrites scoring fields,
        update_case_results / save_case_results overwrite case fields).
        HOWEVER: update_kpi_and_user_stats increments total_cases counters
        unconditionally — calling get_report twice will double-count KPI stats.
        This is a pre-existing bug (out of scope for Task 5); duplicate webhook
        deliveries should be deduplicated by the caller (Task 6/7).
        """
        self.get_results(case)
        self.generate_description(case)
        if case.status == "Done":
            try:
                CortexAnalyzerReports.get_report(case)
            except Exception as e:
                update_cases_logger.error(
                    "Error fetching final report for case %s: %s", case.id, e,
                    exc_info=True,
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
                analyzer__name=(cortex_config.get("analyzers", {}).get("ai", {})),
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
            case.score_ai = analyzer.score
            case.confidence_ai = analyzer.confidence * 10
            case.category_ai = self.get_sub_class(analyzer)
            case.results_ai = analyzer.level.capitalize()
            case.save()

            update_cases_logger.info(
                "AI Mail Analyzer updated for case %s: score=%f, confidence=%f, category=%s",
                case.id,
                case.score_ai,
                case.confidence_ai,
                case.category_ai,
            )

            # Update associated MailInfo
            mail_info = MailInfo.objects.get(mail=eml)
            self.update_mail_models(mail_info, case.category_ai, case.results_ai)

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
