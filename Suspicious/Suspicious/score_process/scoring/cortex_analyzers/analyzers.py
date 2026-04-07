# score_process/scoring/cortex_analyzers/analyzers.py
"""
Analyzer factory — maps analyzer names to implementation classes.
"""
import logging
from typing import Optional

from .utils import normalize_analyzer_name
from .models import AnalyzerResult

from .analyzers_services.base import BaseAnalyzer
from .analyzers_services.google_safebrowsing import AnalyzerGoogleSafeBrowsing
from .analyzers_services.fileinfo import AnalyzerFileinfo
from .analyzers_services.virustotal import AnalyzerVT
from .analyzers_services.misp import AnalyzerMISP
from .analyzers_services.otx import AnalyzerOTXQuery
from .analyzers_services.urlscan import AnalyzerUrlscan
from .analyzers_services.urlhaus import AnalyzerURLhaus
from .analyzers_services.abuseipdb import AnalyzerAbuseIPDB
from .analyzers_services.crowdsec import AnalyzerCrowdsec
from .analyzers_services.circl_hashlookup import AnalyzerCIRCLHashLookup
from .analyzers_services.dshield import AnalyzerDShield
from .analyzers_services.maxmind import AnalyzerMaxMind
from .analyzers_services.mnemonic_pdns import AnalyzerMN_PDNS
from .analyzers_services.zscaler import AnalyzerZscaler
from .analyzers_services.sfs import AnalyzerSFS
from .analyzers_services.hashdd import AnalyzerHashdd
from .analyzers_services.yara import AnalyzerYara
from .analyzers_services.mailheader import AnalyzerMailHeader
from .analyzers_services.ai.service import AnalyzerAI
from .analyzers_services.glimps import AnalyzerGMalware

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerExecutionError(Exception):
    """Raised when an analyzer raises an unexpected exception during .process()."""


class AnalyzerFactory:
    """Maps analyzer names to their implementation classes and runs them."""

    REGISTRY = {
        "googlesafebrowsing": AnalyzerGoogleSafeBrowsing,
        "fileinfo":           AnalyzerFileinfo,
        "virustotal":         AnalyzerVT,
        "misp":               AnalyzerMISP,
        "otxquery":           AnalyzerOTXQuery,
        "urlscan":            AnalyzerUrlscan,
        "urlhaus":            AnalyzerURLhaus,
        "abuseipdb":          AnalyzerAbuseIPDB,
        "crowdsec":           AnalyzerCrowdsec,
        "circlhashlookup":    AnalyzerCIRCLHashLookup,
        "dshield":            AnalyzerDShield,
        "maxmind":            AnalyzerMaxMind,
        "mnemonic":           AnalyzerMN_PDNS,
        "zscaler":            AnalyzerZscaler,
        "stopforumspam":      AnalyzerSFS,
        "hashdd":             AnalyzerHashdd,
        "yara":               AnalyzerYara,
        "mailheader":         AnalyzerMailHeader,
        "ai":                 AnalyzerAI,
        "gmalware":           AnalyzerGMalware,
    }

    @classmethod
    def run(
        cls,
        summary,
        full,
        analyzer_name: str,
        data,
        data_type: str,
        case_id=None,
    ) -> AnalyzerResult:
        """
        Instantiate and run the appropriate analyzer.

        Raises AnalyzerExecutionError on unexpected failures so the caller
        can route to handle_failure rather than silently scoring 0.
        Falls back to BaseAnalyzer for unknown analyzer names (no silent None).
        """
        normalized    = normalize_analyzer_name(analyzer_name)
        analyzer_cls  = cls.REGISTRY.get(normalized, BaseAnalyzer)

        if analyzer_cls is BaseAnalyzer and normalized not in cls.REGISTRY:
            logger.warning(
                "Unknown analyzer %r (normalized: %r) — using BaseAnalyzer fallback.",
                analyzer_name, normalized,
            )

        try:
            analyzer = analyzer_cls(
                summary=summary,
                full=full,
                data=data,
                analyzer_name=analyzer_name,
                data_type=data_type,
                case_id=case_id,
            )
            return AnalyzerResult(**analyzer.process())
        except Exception as exc:
            raise AnalyzerExecutionError(
                "Analyzer %r failed: %s" % (analyzer_name, exc)
            ) from exc


class CortexAnalyzerService:
    """Entry point for analyzer execution and result normalisation."""

    @staticmethod
    def create_report(
        summary,
        full,
        analyzer_name: str,
        data,
        data_type: str,
        case_id=None,
    ) -> AnalyzerResult:
        """
        Run an analyzer and return a normalised AnalyzerResult.

        This is the single exception boundary for the Cortex pipeline.
        AnalyzerFactory.run() raises AnalyzerExecutionError on failure;
        we catch it here and return a neutral result so the report is
        recorded as a failure (score=0 confidence=0) rather than crashing
        the whole case pipeline.
        """
        logger.info(
            "[service] Running analyzer=%s data_type=%s.", analyzer_name, data_type
        )

        try:
            return AnalyzerFactory.run(
                summary=summary,
                full=full,
                analyzer_name=analyzer_name,
                data=data,
                data_type=data_type,
                case_id=case_id,
            )
        except Exception as exc:
            logger.error(
                "Analyzer service failure for %s: %s", analyzer_name, exc, exc_info=True
            )
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                data=str(data),
                score=0,
                confidence=0,
                category="Unknown",
                level="unknown",
                details={},
            )