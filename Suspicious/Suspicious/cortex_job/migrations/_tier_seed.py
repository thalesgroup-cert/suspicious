"""Shared tier-seed table. Imported by the data migration and its test so the
mapping has one source of truth. Match is by case-insensitive name prefix."""

TIER_1_PREFIXES = ("VirusTotal", "MISP", "GoogleThreatIntelligence", "GTI")
TIER_2_PREFIXES = ("AI_Mail_Analyzer", "Yara", "ThreatGrid", "CIRCLHashlookup", "Cuckoo", "Hybrid")


def tier_for(analyzer_name: str) -> int:
    name = (analyzer_name or "").lower()
    if any(name.startswith(p.lower()) for p in TIER_1_PREFIXES):
        return 1
    if any(name.startswith(p.lower()) for p in TIER_2_PREFIXES):
        return 2
    return 3
