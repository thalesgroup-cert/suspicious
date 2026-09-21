"""DomainMailSPFDMARC — SPF / DMARC posture of a domain.

The upstream analyzer maps "no DMARC record" to a `malicious` taxonomy and
"no SPF record" to `malicious`/`suspicious`. Via DefaultTaxonomyParser that
became a real scoring vote, so a perfectly legit domain that just doesn't send
authenticated mail (neverssl.com, github.io, any parked/service domain) was
forced to Suspicious — often Dangerous — as a bare domain IOC.

Weak mail auth is *not* evidence a domain is malicious: phishing domains
routinely publish flawless SPF/DMARC, and legit domains routinely publish
none. It's context, not a verdict. The mail road already does its own real
auth-posture analysis where the sender domain actually matters. So this parser
always maps to "info" (-> no-data) and carries the SPF/DMARC records + errors
in `details` for the analyst.
"""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence


def _section(block: Any, key: str) -> dict:
    if isinstance(block, dict) and isinstance(block.get(key), dict):
        return block[key]
    return {}


class DomainMailSpfDmarcParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="domain_mail_spf_dmarc",
                                cortex_names=("DomainMailSPFDMARC_1_2",),
                                data_types=("domain", "fqdn"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        block = full.get("DomainMailSPFDMARC") if isinstance(full, dict) else None
        spf, dmarc = _section(block, "spf"), _section(block, "dmarc")

        score, confidence = get_level_score_confidence("info")
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level="info",
            category=[f"SPF {'ok' if spf.get('valid') else 'missing/invalid'}",
                      f"DMARC {'ok' if dmarc.get('valid') else 'missing/invalid'}"],
            details={"spf": {"record": spf.get("record"), "valid": spf.get("valid"),
                             "error": spf.get("error")},
                     "dmarc": {"record": dmarc.get("record"), "valid": dmarc.get("valid"),
                               "error": dmarc.get("error")}},
        )
