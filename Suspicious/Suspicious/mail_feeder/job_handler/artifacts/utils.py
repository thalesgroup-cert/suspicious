import logging

from common.safe_exec import make_safe_execution

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

safe_execution = make_safe_execution("ArtifactService", logger)
