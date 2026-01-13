from pymisp import ExpandedPyMISP
from .models import MISPSettings
import logging

logger = logging.getLogger(__name__)

class MISPClient:
    def __init__(self, config):
        if not hasattr(config, "url") or not hasattr(config, "key"):
            raise ValueError("Invalid MISP config: missing url or key")

        self.url = config.url
        self.key = config.key
        self.misp = self._connect()


    def _connect(self) -> ExpandedPyMISP:
        try:
            misp = ExpandedPyMISP(str(self.url), self.key, ssl=False)
            logger.info("MISP instance created successfully.")
            return misp
        except Exception as e:
            logger.error(f"Failed to create MISP instance: {e}", exc_info=True)
            raise
