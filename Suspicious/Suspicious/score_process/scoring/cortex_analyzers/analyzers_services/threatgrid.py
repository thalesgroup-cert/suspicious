"""
ThreatGrid / Sandbox analyzer — pass-through (base class handles scoring).
"""
from __future__ import annotations
from typing import Any, Dict
from .base import BaseAnalyzer


class AnalyzerThreatGrid(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        return super().process()