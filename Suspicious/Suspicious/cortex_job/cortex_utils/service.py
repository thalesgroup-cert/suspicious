import logging
from cortex4py.api import Api
from models import CortexJobRequest, Analyzer, AnalyzerReport, CortexJobData
from utils import load_config, fetch_mail_logger

logger = logging.getLogger(__name__)

class CortexJob:
    def __init__(self, config: CortexJobRequest):
        """
        Initialize the CortexJob with the configuration.

        Args:
            config (CortexJobRequest): Configuration for the Cortex job.
        """
        self.api_url = config.api_url or "https://cortex.example.com"
        self.api_key = config.api_key or "your_api_key_here"
        self.proxies = config.proxies or {"http": "", "https": ""}
        self.api = None

        # Initialize Cortex API connection
        try:
            self.api = Api(self.api_url, self.api_key, proxies=self.proxies)
        except Exception as e:
            fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")

    def launch_cortex_jobs(self, data: CortexJobData):
        """
        Launch Cortex jobs based on the given data.

        Args:
            data (CortexJobData): The data object to be analyzed.

        Returns:
            List[str]: List of job IDs for the launched Cortex jobs.
        """
        analyzers = self.get_analyzers_by_type(data.data_type)

        # Run analyzers and collect job IDs
        job_ids = []
        for analyzer in analyzers:
            try:
                report = self.run_analyzer(analyzer, data)
                if report and hasattr(report, "id"):
                    job_ids.append(report.id)
            except Exception as e:
                fetch_mail_logger.error(f"Error running analyzer {analyzer.name}: {e}")
        
        return job_ids

    def run_analyzer(self, analyzer: Analyzer, data: CortexJobData) -> Optional[AnalyzerReport]:
        """
        Run a Cortex analyzer on the given data.

        Args:
            analyzer (Analyzer): The analyzer to run.
            data (CortexJobData): The data to be analyzed.

        Returns:
            Optional[AnalyzerReport]: The report object if successful, None otherwise.
        """
        payload = {"data": data.data_value, "dataType": data.data_type, "tlp": 2}
        try:
            report = self.api.analyzers.run_by_name(analyzer.name, payload)
            return AnalyzerReport(cortex_job_id=report.id, type=data.data_type, analyzer=analyzer, level="info", confidence=0, score=0, report_summary={}, report_full={}, report_taxonomy={})
        except Exception as e:
            fetch_mail_logger.error(f"Error running analyzer '{analyzer.name}' on {data.data_type}: {e}")
            return None

    def get_analyzers_by_type(self, data_type: str) -> List[Analyzer]:
        """
        Retrieve analyzers based on the data type.

        Args:
            data_type (str): The type of data being analyzed.

        Returns:
            List[Analyzer]: List of analyzers for the given data type.
        """
        try:
            return self.api.analyzers.get_by_type(data_type)
        except Exception as e:
            fetch_mail_logger.error(f"Error fetching analyzers for type '{data_type}': {e}")
            return []
