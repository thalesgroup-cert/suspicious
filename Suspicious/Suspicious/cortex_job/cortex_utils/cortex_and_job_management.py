import logging

import pybreaker
from cortex4py.exceptions import NotFoundError
from django.db import transaction

from common.http_client import get_breaker, RETRY
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi  # noqa: F401 -- patch point in tests
from cortex_job.migrations._tier_seed import tier_for
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from mail_feeder.models import MailBody, MailHeader

# Logger setup
logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


# Lazy Cortex configuration accessor
def _get_cortex_config() -> dict:
    """Cortex config via the runtime accessor; empty dict on failure."""
    try:
        from settings.config import get_section
        return get_section("integrations.cortex")
    except Exception as exc:
        fetch_mail_logger.error(f"Could not load cortex config: {exc}")
        return {}


DEFAULT_AI_ANALYZER_NAME = "AI_Mail_Analyzer"


def ai_analyzer_name() -> str:
    """Name of the Analyzer row that carries the AI vote (and its weight): the configured
    integrations.cortex.analyzers.ai, else DEFAULT_AI_ANALYZER_NAME. The ai_model connector
    needs no Cortex analyzer, so the key may be absent."""
    return _get_cortex_config().get("analyzers", {}).get("ai") or DEFAULT_AI_ANALYZER_NAME


# Cortex keeps a job InProgress forever when it restarts mid-run, so this is the only thing that
# frees a case in that state. Long enough for a sandbox detonation, short enough to notice a lost job.
DEFAULT_STALE_JOB_TIMEOUT_SECONDS = 7200


def __getattr__(name):
    if name in ("API_URL", "API_KEY", "STALE_JOB_TIMEOUT_SECONDS"):
        cc = _get_cortex_config()
        if name == "API_URL":
            return cc.get("url", "https://cortex.example.com")
        if name == "API_KEY":
            return cc.get("api_key", "your_api_key_here")
        return int(cc.get("stale_job_timeout_seconds", DEFAULT_STALE_JOB_TIMEOUT_SECONDS))
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
    def launch_cortex_jobs(self, value, data_type, case):
        """Start the analyzers every enabled analysis engine selects for ``value``.
        Forwards to connectors.engines.dispatch; returns the ledger job ids."""
        from connectors import engines  # lazy: keeps the registry out of migration imports

        return engines.dispatch(value, data_type, case)

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
    def get_analyzer_db(analyzer, source="cortex"):
        """
        Retrieve an Analyzer object from the database, or create a new one if it does not exist.

        Args:
            analyzer: An object with `id` and `name` attributes (a Cortex analyzer or a
                CatalogEntry whose id is already the ledger id).
            source: The connector that owns a newly created row.

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
                    tier=tier_for(analyzer.name),
                    source=source,
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
    # ponytail: no longer read; kept because older tests clear them. Job state lives in the
    # per-reconcile cache handed to connectors.engines.refresh.
    _job_cache = {}
    _report_cache = {}

    def __init__(self):
        self.case = None
        self._fetch_cache = {}  # one per manager, so one per reconcile_case_core call

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

        from connectors.base import FETCH_GONE, FETCH_RESULT, FETCH_UNKNOWN, FetchResult
        from connectors.engines import update_report

        job_id = report_instance.cortex_job_id
        job = cls.get_job_from_api(job_id)
        if job == "old_job":
            fetched = FetchResult(FETCH_GONE)
        elif not job:
            fetched = FetchResult(FETCH_UNKNOWN)
        else:
            report = cls.get_report_from_api(job_id) or {}
            fetched = FetchResult(
                FETCH_RESULT, job.status, report.get("summary"), report.get("full"), data_type=job.dataType,
            )
        stale_timeout = int(_get_cortex_config().get("stale_job_timeout_seconds", DEFAULT_STALE_JOB_TIMEOUT_SECONDS))
        return update_report(report_instance, fetched, stale_timeout)

    @staticmethod
    def get_job_from_api(job_id):
        """Fetch a Cortex job by ID.

        Returns the job on success. Returns the "old_job" sentinel ONLY when
        Cortex has positively confirmed the job no longer exists (HTTP 404 ->
        cortex4py NotFoundError): that's the one condition under which
        get_cortex_jobs_results permanently marks a report "Deleted". Any
        other failure (network error, breaker open, auth error, 5xx, ...)
        returns None instead, so the caller leaves the report's current
        status untouched: a later poll can retry, and the existing
        stale-job timeout in get_cortex_jobs_results is what eventually
        gives up on a job that's transiently unreachable for too long. A job
        that briefly couldn't be reached is not the same as a job Cortex
        says is gone: collapsing both to "Deleted" here would silently and
        irreversibly discard in-progress analyzer results on a network blip.
        """
        cc = _get_cortex_config()
        try:
            api = SessionCortexApi(
                cc.get("url", "https://cortex.example.com"),
                cc.get("api_key", "your_api_key_here"),
                proxies={"http": "", "https": ""},
            )
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
            return None

        try:
            job = _fetch_job(api, job_id)
            if job:
                return job
        except NotFoundError:
            return "old_job"
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning(
                "[breaker:cortex] open, get_job_from_api skipped for job %s: %s", job_id, e
            )
        except Exception as e:
            update_cases_logger.error(
                f"Error fetching job {job_id}: {e}", exc_info=True
            )
        return None

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
                    "[breaker:cortex] open, get_report_from_api skipped for job %s: %s", job_id, e
                )
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching report for job {job_id}: {e}", exc_info=True
                )
        return None

    def get_new_reports(self, data_type, filter_kwargs):
        """
        Fetch all non-Deleted AnalyzerReport objects for this data_type
        and artifact filter.
        """
        return AnalyzerReport.objects.filter(
            type=data_type, **filter_kwargs
        ).exclude(status="Deleted")

    def update_single_job(self, caj) -> None:
        """Sync one CaseAnalyzerJob and its report through its engine (connectors.engines.refresh)."""
        from connectors.engines import refresh

        refresh(caj, self._fetch_cache)
