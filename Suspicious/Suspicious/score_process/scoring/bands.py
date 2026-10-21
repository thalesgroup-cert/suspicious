# score_process/scoring/bands.py
"""Categorical-band vocabulary shared across the scoring roads.

The IOC road (apply.finalise_ioc_group), the derived-observable escalation
(cortex_job.cortex_utils.derived_observables), and the mail-road embedded
escalation all map the same four ObservableVerdict bands onto scores, the
legacy IOC-level vocabulary, and a rank. One home so a change propagates.
"""
from __future__ import annotations

# ObservableVerdict.band -> comparable rank (Safe and Inconclusive tie low).
_BAND_RANK = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}

# worst-of ordering when picking the dominant embedded verdict.
# NOTE: distinct from observable_engine._BAND_ORDER (3 keys, no Inconclusive).
# This one includes Inconclusive=1 for worst-of ordering across mixed verdicts.
_BAND_ORDER = {"Safe": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}

# band -> legacy ioc_level string that admin filters + cross-case reuse read.
_BAND_TO_IOC_LEVEL = {
    "Safe": "safe", "Inconclusive": "info",
    "Suspicious": "suspicious", "Dangerous": "malicious",
}

# band -> the 0-10 numeric score persisted on the observable / artifact rows.
_DERIVED_SCORE = {"Safe": 2, "Suspicious": 6, "Dangerous": 9, "Inconclusive": 5}

# ioc_level markers set by the deny/allow-list paths — never overwritten by a
# categorical re-score.
_STICKY_IOC_LEVELS = {"critical", "SAFE-ALLOW_LISTED"}


def sticky_holds(obj) -> bool:
    """True when obj's sticky ioc_level still applies. An allow-listed marker
    lapses once the domain became deny-listed, Watcher-monitored or campaign."""
    level = getattr(obj, "ioc_level", "info")
    if level not in _STICKY_IOC_LEVELS:
        return False
    if level != "SAFE-ALLOW_LISTED":
        return True
    from urllib.parse import urlparse

    from domain_process.models import Domain
    from settings.allow_lists import overrides_allow_list

    host = getattr(obj, "value", None) or urlparse(getattr(obj, "address", "") or "").hostname
    domain = Domain.objects.filter(value=host).first() if host else None
    return not overrides_allow_list(domain)
