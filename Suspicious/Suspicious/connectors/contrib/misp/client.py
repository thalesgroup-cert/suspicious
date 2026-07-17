"""
MISP client wrapper.
"""
from __future__ import annotations
import logging
from pymisp import ExpandedPyMISP
from .models import MISPConfig

logger = logging.getLogger(__name__)


class MISPClient:
    def __init__(self, config: MISPConfig) -> None:
        if not hasattr(config, "url") or not hasattr(config, "key"):
            raise ValueError("Invalid MISP config: missing url or key.")
        self.url    = str(config.url)
        self.key    = config.key
        self.ssl    = getattr(config, "ssl_verify", False)
        self.misp   = self._connect()

    def _connect(self) -> ExpandedPyMISP:
        try:
            instance = ExpandedPyMISP(self.url, self.key, ssl=self.ssl)
            logger.info("MISP instance connected to %s.", self.url)
            return instance
        except Exception as exc:
            logger.error("Failed to connect to MISP at %s: %s", self.url, exc, exc_info=True)
            raise