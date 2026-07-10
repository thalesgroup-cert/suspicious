"""CIRCL hashlookup — known-malicious / known-good (NSRL) / unknown hash."""
from __future__ import annotations

from typing import Any

from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from ..default import get_level_score_confidence


class CirclHashlookupParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="circl_hashlookup", cortex_names=("CIRCLHashlookup_1_1",),
                                data_types=("hash", "file"))

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        full = full if isinstance(full, dict) else {}
        message = str(full.get("message", "")).lower()
        filename = full.get("FileName") or full.get("filename")

        if full.get("KnownMalicious"):
            level = "malicious"
            category = [f"Known malicious: {full['KnownMalicious']}"]
        elif "non existing" in message or not full or (not filename and not full.get("source")):
            level = "info"
            category = ["Unknown hash"]
        else:
            level = "safe"
            category = [filename or "Known good"]

        score, confidence = get_level_score_confidence(level)
        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=category,
            details={"FileName": filename, "source": full.get("source"),
                     "KnownMalicious": full.get("KnownMalicious")},
        )
