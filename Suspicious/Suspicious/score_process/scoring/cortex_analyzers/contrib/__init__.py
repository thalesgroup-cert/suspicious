"""Builtin bespoke analyzer parsers (path:attr, mirrors connectors.contrib)."""
BUILTIN_ANALYZER_PARSERS = [
    "score_process.scoring.cortex_analyzers.contrib.ai_mail:AiMailParser",
    "score_process.scoring.cortex_analyzers.contrib.zscaler:ZscalerParser",
    "score_process.scoring.cortex_analyzers.contrib.virustotal:VirusTotalGetReportParser",
    "score_process.scoring.cortex_analyzers.contrib.urlscan:UrlscanSearchParser",
    "score_process.scoring.cortex_analyzers.contrib.misp:MispParser",
    "score_process.scoring.cortex_analyzers.contrib.circl_hashlookup:CirclHashlookupParser",
    "score_process.scoring.cortex_analyzers.contrib.spamhaus_dbl:SpamhausDblParser",
    "score_process.scoring.cortex_analyzers.contrib.threatminer:ThreatMinerParser",
    "score_process.scoring.cortex_analyzers.contrib.team_cymru_mhr:TeamCymruMhrParser",
    "score_process.scoring.cortex_analyzers.contrib.domain_mail_spf_dmarc:DomainMailSpfDmarcParser",
    "score_process.scoring.cortex_analyzers.contrib.cyberprotect:CyberprotectThreatScoreParser",
]
