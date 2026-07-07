"""Builtin bespoke analyzer parsers (path:attr, mirrors connectors.contrib)."""
BUILTIN_ANALYZER_PARSERS = [
    "score_process.scoring.cortex_analyzers.contrib.ai_mail:AiMailParser",
    "score_process.scoring.cortex_analyzers.contrib.zscaler:ZscalerParser",
    "score_process.scoring.cortex_analyzers.contrib.virustotal:VirusTotalGetReportParser",
    "score_process.scoring.cortex_analyzers.contrib.urlscan:UrlscanSearchParser",
    "score_process.scoring.cortex_analyzers.contrib.misp:MispParser",
]
