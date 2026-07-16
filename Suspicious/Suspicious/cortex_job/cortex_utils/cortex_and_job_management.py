import json
import logging

import pybreaker
from django.db import transaction
from django.utils import timezone

from common.http_client import get_breaker, RETRY
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from mail_feeder.models import MailBody, MailArchive, MailInfo, MailHeader
from case_handler.models import Result

# ------------------------
# Logger setup
# ------------------------
logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


# ------------------------
# Lazy Cortex configuration accessor
# ------------------------
def _get_cortex_config() -> dict:
    """Cortex config via the runtime accessor; empty dict on failure."""
    try:
        from settings.config import get_section
        return get_section("integrations.cortex")
    except Exception as exc:
        fetch_mail_logger.error(f"Could not load cortex config: {exc}")
        return {}


def __getattr__(name):
    if name in ("API_URL", "API_KEY", "STALE_JOB_TIMEOUT_SECONDS"):
        cc = _get_cortex_config()
        if name == "API_URL":
            return cc.get("url", "https://cortex.example.com")
        if name == "API_KEY":
            return cc.get("api_key", "your_api_key_here")
        return int(cc.get("stale_job_timeout_seconds", 86400))
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
        cortex_config = _get_cortex_config()
        self.api_url = api_url or cortex_config.get("url", "https://cortex.example.com")
        self.api_key = api_key or cortex_config.get("api_key", "your_api_key_here")

        self.proxies = (
            proxies if isinstance(proxies, dict) else {"http": "", "https": ""}
        )

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
        cortex_config = _get_cortex_config()
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
            return None

        archive = getattr(value, "archive", None)
        if not archive or not hasattr(archive, "tmp_path"):
            fetch_mail_logger.warning(
                f"Invalid value or missing archive for data_type '{data_type}'"
            )
            return None

        if archive.tmp_path.endswith(".eml"):
            fetch_mail_logger.info("Skipping AI analyzer for .eml file")
            return None

        try:
            cortex_config = _get_cortex_config()
            ai_analyzer_name = (cortex_config.get("analyzers", {}).get("ai", {}))
            analyzer = self.api.analyzers.get_by_name(ai_analyzer_name)
            if not analyzer:
                fetch_mail_logger.warning(f"AI analyzer '{ai_analyzer_name}' not found")
                return None

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

        cortex_config = _get_cortex_config()
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

        cortex_config = _get_cortex_config()
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
            data_value = data

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

        try:
            with transaction.atomic():
                return Analyzer.objects.create(
                    analyzer_cortex_id=analyzer.id,
                    name=analyzer.name,
                    weight=0.2,
                )
        except Exception as e:
            fetch_mail_logger.warning(
                f"Error creating analyzer '{analyzer.name}': {e!s}"
            )

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

        if analyzer_report.pk:
            analyzer_report.save(update_fields=[data_type])
        else:
            analyzer_report.save()

class CortexJobManager:
    _job_cache = {}
    _report_cache = {}

    def __init__(self):
        self.case = None
        CortexJobManager._job_cache.clear()
        CortexJobManager._report_cache.clear()

        _cc = _get_cortex_config()
        self.api_urls = _cc.get("url", "https://cortex.example.com")
        self.api_keys = _cc.get("api_key", "your_api_key_here")

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
                stale_timeout = int(_get_cortex_config().get("stale_job_timeout_seconds", 86400))
                if age > stale_timeout:
                    update_cases_logger.warning(
                        "Auto-failing stale %s report cortex_job_id=%s after %.0fs",
                        report_instance.status, job_id, age,
                    )
                    report_instance.status = "Failure"
                    report_instance.save(update_fields=["status"])

        return report_instance.status

    @staticmethod
    def get_job_from_api(job_id):
        cc = _get_cortex_config()
        try:
            api = SessionCortexApi(
                cc.get("url", "https://cortex.example.com"),
                cc.get("api_key", "your_api_key_here"),
                proxies={"http": "", "https": ""},
            )
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
            api = None
        for api in [api]:
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
        cc = _get_cortex_config()
        try:
            api = SessionCortexApi(
                cc.get("url", "https://cortex.example.com"),
                cc.get("api_key", "your_api_key_here"),
                proxies={"http": "", "https": ""},
            )
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
            api = None
        for api in [api]:
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

        if report_instance.status != job.status:
            report_instance.status = job.status
            updated_fields.append("status")

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

    def get_new_reports(self, data_type, filter_kwargs):
        """
        Fetch all non-Deleted AnalyzerReport objects for this data_type
        and artifact filter. Cortex API calls are deduplicated via the
        class-level _job_cache / _report_cache during a single tick.
        """
        return AnalyzerReport.objects.filter(
            type=data_type, **filter_kwargs
        ).exclude(status="Deleted")

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

    def manage_ai_jobs(self, case):
        """
        Manage AI jobs for a case.

        Updates the case and MailInfo models if AI analysis has completed.

        Args:
            case (Case): The case to manage.
        """
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

        try:
            cortex_config = _get_cortex_config()
            analyzer = AnalyzerReport.objects.get(
                analyzer__name=(cortex_config.get("analyzers", {}).get("ai", {})),
                file=mail_archive.archive,
            )
            if analyzer is None:
                raise AnalyzerReport.DoesNotExist

            if analyzer.status == "Failure":
                update_cases_logger.info(
                    "AI Mail Analyzer report is Failure for case %s — marked Inconclusive.",
                    case.id,
                )
                case.results_ai = Result.INCONCLUSIVE
                case.save(update_fields=["results_ai"])
                return
            update_cases_logger.info("AI Mail Analyzer report found: %s", analyzer)
        except AnalyzerReport.DoesNotExist:
            update_cases_logger.info(
                "No AI Mail Analyzer report found for archive file: %s",
                mail_archive.archive,
            )
            last_job = (
                CaseAnalyzerJob.objects
                .filter(case=case, analyzer__name=analyzer.analyzer.name)
                .order_by("-created_at")
                .first()
            )
            if last_job is None or last_job.status == CaseAnalyzerJob.STATUS_FAILURE:
                case.results_ai = Result.INCONCLUSIVE
                case.save(update_fields=["results_ai"])
                update_cases_logger.info(
                    "AI Mail Analyzer unavailable for case %s — marked Inconclusive.",
                    case.id,
                )
            return
        except Exception as e:
            update_cases_logger.error("Error retrieving analyzer report: %s", e)
            return

        try:
            case.score_ai = analyzer.score
            case.confidence_ai = analyzer.confidence
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

            classification_lower = (classification or "").strip().lower()
            sub_class_lower = (sub_classification or "").strip().lower()

            if classification_lower in {"classic_phishing", "whaling", "clone"}:
                mail_info.is_phishing = True

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
