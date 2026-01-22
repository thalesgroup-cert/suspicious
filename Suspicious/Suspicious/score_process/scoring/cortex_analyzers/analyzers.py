import logging
from .utils import normalize_analyzer_name
from .models import AnalyzerResult

# Import all analyzers
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
        "yara": AnalyzerYara,
        "mailheader": AnalyzerMailHeader,
        "ai": AnalyzerAI,
        "gmalware": AnalyzerGMalware,
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
