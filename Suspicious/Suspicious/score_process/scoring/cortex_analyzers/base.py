"""Analyzer parser contract: manifest + run() template (pending → allow-list → parse)."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Optional

from .result import AnalyzerResult, PENDING
from .allow_list import check_allow_list

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def is_pending(summary: Any, full: Any, status: Optional[str] = None) -> bool:
    """True when the analyzer job is not a finished success — must not be scored."""
    if status is not None and status != "Success":
        return True
    if not summary and not full:
        return True
    for payload in (summary, full):
        if isinstance(payload, dict) and "ongoing" in payload:
            return True
    return False


@dataclass(frozen=True)
class AnalyzerManifest:
    name: str
    cortex_names: tuple[str, ...]
    data_types: tuple[str, ...] = ()


class AnalyzerParser(ABC):
    manifest: ClassVar[AnalyzerManifest]

    def __init__(self, *, analyzer_name: str, data: Any,
                 data_type: Optional[str] = None, case_id: Optional[int] = None) -> None:
        self.analyzer_name = analyzer_name
        self.data = data
        self.data_name = str(data)
        self.type = data_type
        self.case_id = case_id

    def run(self, summary: Any, full: Any, status: Optional[str] = None):
        """Template method — NOT overridden. pending → allow-list → parse()."""
        if is_pending(summary, full, status):
            logger.debug("[%s] pending — not scoring.", self.analyzer_name)
            return PENDING

        try:
            allow = check_allow_list(self.data_name, self.type)
            for value in allow.model_dump().values():
                if value is not None:
                    return AnalyzerResult(
                        analyzer_name=self.analyzer_name, data=self.data_name,
                        score=0, confidence=100, level="safe",
                        category=[value], details={"whitelist": value},
                    )
        except Exception as exc:
            logger.error("[%s] allow-list error: %s", self.analyzer_name, exc, exc_info=True)

        return self.parse(summary, full)

    @abstractmethod
    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        """Map this analyzer's JSON to an AnalyzerResult. Override for bespoke shapes."""
