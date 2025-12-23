from pymisp import ExpandedPyMISP
from .models import MISPSettings
import logging

logger = logging.getLogger(__name__)

class MISPClient:
    def __init__(self, config: MISPSettings, primary: bool = True):
        if primary:
            self.url = config.suspicious.url
            self.key = config.suspicious.key
        else:
            self.url = config.security.url
            self.key = config.security.key
        self.misp = self._connect()

    def _connect(self) -> ExpandedPyMISP:
        try:
            misp = ExpandedPyMISP(str(self.url), self.key, ssl=False)
            logger.info("MISP instance created successfully.")
            return misp
        except Exception as e:
            logger.error(f"Failed to create MISP instance: {e}", exc_info=True)
            raise
