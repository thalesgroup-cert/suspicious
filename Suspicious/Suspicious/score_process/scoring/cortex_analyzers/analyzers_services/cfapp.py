# analyzers_services/cfapp.py
"""
CFApp analyzer — pass-through (base class handles all scoring).
"""
from __future__ import annotations
from typing import Any, Dict
from .base import BaseAnalyzer


class AnalyzerCFApp(BaseAnalyzer):
    def process(self) -> Dict[str, Any]:
        return super().process()