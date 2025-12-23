import logging
from .utils import normalize_analyzer_name
from .models import AnalyzerResult

# Import all analyzers
from .cortex_analyzers.base import BaseAnalyzer
from .cortex_analyzers.googlesafebrowsing import AnalyzerGoogleSafeBrowsing
from .cortex_analyzers.fileinfo import AnalyzerFileinfo
from .cortex_analyzers.virustotal import AnalyzerVT
from .cortex_analyzers.misp import AnalyzerMISP
from .cortex_analyzers.otxquery import AnalyzerOTXQuery
from .cortex_analyzers.urlscan import AnalyzerUrlscan
from .cortex_analyzers.urlhaus import AnalyzerURLhaus
from .cortex_analyzers.abuseipdb import AnalyzerAbuseIPDB
from .cortex_analyzers.crowdsec import AnalyzerCrowdsec
from .cortex_analyzers.circlhashlookup import AnalyzerCIRCLHashLookup
from .cortex_analyzers.dshield import AnalyzerDShield
from .cortex_analyzers.maxmind import AnalyzerMaxMind
from .cortex_analyzers.mnemonic import AnalyzerMN_PDNS
from .cortex_analyzers.zscaler import AnalyzerZscaler
from .cortex_analyzers.stopforumspam import AnalyzerSFS
from .cortex_analyzers.hashdd import AnalyzerHashdd
from .cortex_analyzers.yara import AnalyzerYaraSuspicious, AnalyzerYaraTasp
from .cortex_analyzers.mailheader import AnalyzerMailHeader
from .cortex_analyzers.ai.service import AnalyzerAI

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerFactory:
    """
    Maps analyzer names to their respective analyzer classes.
    """

    REGISTRY = {
        "googlesafebrowsing": AnalyzerGoogleSafeBrowsing,
        "fileinfo": AnalyzerFileinfo,
        "virustotal": AnalyzerVT,
        "misp": AnalyzerMISP,
        "otxquery": AnalyzerOTXQuery,
        "urlscan": AnalyzerUrlscan,
        "urlhaus": AnalyzerURLhaus,
        "abuseipdb": AnalyzerAbuseIPDB,
        "crowdsec": AnalyzerCrowdsec,
        "circlhashlookup": AnalyzerCIRCLHashLookup,
        "dshield": AnalyzerDShield,
        "maxmind": AnalyzerMaxMind,
        "mnemonic": AnalyzerMN_PDNS,
        "zscaler": AnalyzerZscaler,
        "stopforumspam": AnalyzerSFS,
        "hashdd": AnalyzerHashdd,
        "yara": AnalyzerYaraSuspicious,
        "yaratasp": AnalyzerYaraTasp,
        "mailheader": AnalyzerMailHeader,
        "ai": AnalyzerAI,
    }

    @classmethod
    def run(
        cls,
        summary,
        full,
        analyzer_name,
        data,
        data_type,
        case_id=None,
    ) -> AnalyzerResult:
        normalized = normalize_analyzer_name(analyzer_name)
        analyzer_cls = cls.REGISTRY.get(normalized, BaseAnalyzer)

        try:
            analyzer = analyzer_cls(
                summary=summary,
                full=full,
                data=data,
                analyzer_name=analyzer_name,
                data_type=data_type,
                case_id=case_id
            )
            return AnalyzerResult(**analyzer.process())
        except Exception as exc:
            logger.error("Analyzer failure for %s: %s", analyzer_name, exc, exc_info=True)
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                data=data,
                score=0,
                confidence=0,
                category="Unknown",
                level="unknown",
                details={},
            )
