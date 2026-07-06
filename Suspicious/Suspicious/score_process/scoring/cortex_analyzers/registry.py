"""Resolve the parser for a Cortex Analyzer row by DB identity (name or cortex id)."""
from __future__ import annotations

import logging
from importlib import import_module

from .base import AnalyzerParser
from .default import DefaultTaxonomyParser

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerParserRegistry:
    def __init__(self) -> None:
        self._by_key: dict[str, type[AnalyzerParser]] = {}
        self._errors: dict[str, str] = {}
        self._discovered = False

    def discover(self) -> None:
        if self._discovered:
            return
        self._discovered = True
        from .contrib import BUILTIN_ANALYZER_PARSERS
        for path in BUILTIN_ANALYZER_PARSERS:
            module_path, _, attr = path.partition(":")
            try:
                cls = getattr(import_module(module_path), attr)
                for key in cls.manifest.cortex_names:
                    self._by_key[key] = cls
            except Exception as exc:  # isolate a bad builtin
                self._errors[path] = str(exc)
                logger.exception("Failed to load analyzer parser %s", path)

    def resolve(self, analyzer) -> type[AnalyzerParser]:
        self.discover()
        for key in (getattr(analyzer, "name", None),
                    getattr(analyzer, "analyzer_cortex_id", None)):
            if key and key in self._by_key:
                return self._by_key[key]
        return DefaultTaxonomyParser

    @property
    def errors(self) -> dict[str, str]:
        return dict(self._errors)


registry = AnalyzerParserRegistry()
