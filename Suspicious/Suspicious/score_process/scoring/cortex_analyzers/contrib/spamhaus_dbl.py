"""SpamhausDBL — the upstream analyzer always self-tags its taxonomy at
"info" level (see ghcr.io/thehive-project/spamhausdbl:1's
spamhausdbl.py:summary()) and puts the real signal only in the
`classification` value, e.g. {"return_code": "127.0.1.2", "classification":
"Spam"}. DefaultTaxonomyParser takes the max taxonomy *level*, so every DBL
hit — including active malware/botnet listings — fell through to "info",
which the categorical engine (score_process.scoring.sources) treats as no
signal at all ("no-data"). This parser reads `classification` directly.

Severity per Spamhaus's own DBL return-code reference
(https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291): Malware/Botnet
C&C listings mean the domain is active malicious infrastructure right now
-> malicious. Spam/Phishing listings and the "Abused legit ..." variants
(a compromised *legitimate* domain, not inherently malicious
infrastructure) are a real but lower-confidence signal -> suspicious, which
also matches how the categorical engine already treats this analyzer's
tier (contextual/low-trust source -> capped at Suspicious regardless).
Query-level responses (rate-limited, malformed query, no record) aren't a
verdict about the domain at all -> info / no-data, same as before.
"""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence

_MALICIOUS = {"Malware", "Botnet C&C"}
_SUSPICIOUS = {
    "Spam", "Phishing",
    "Abused legit spam", "Abused spammed redirector",
    "Abused legit phish", "Abused legit malware", "Abused legit Botnet C&C",
}
# Everything else (Clean, NXDOMAIN's mapped classification, query-level
# responses like "IP queries prohibited"/"Timeout"/"NoAnswer", or a missing
# classification) falls through to the "safe"/"info" default below.
_SAFE = {"Clean"}


class SpamhausDblParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="spamhaus_dbl", cortex_names=("SpamhausDBL_1_0",),
                                data_types=("domain", "fqdn"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}
        classification = full.get("classification")

        if classification in _MALICIOUS:
            level = "malicious"
        elif classification in _SUSPICIOUS:
            level = "suspicious"
        elif classification in _SAFE:
            level = "safe"
        else:
            level = "info"  # query-level response or nothing to go on

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=[classification] if classification else [],
            details={"return_code": full.get("return_code"), "classification": classification},
        )
