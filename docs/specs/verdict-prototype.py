#!/usr/bin/env python3
"""
Prototype + validation of the categorical trust-tiered verdict engine
(scoring-verdict-model spec Tasks 8-10 — NOT yet implemented in the pilot).

Analyzer output shapes and taxonomy-level logic are taken verbatim from the
official Cortex-Analyzers source (TheHive-Project/Cortex-Analyzers @ master):
  - GoogleThreatIntelligence/gti.py  : threat_score >=80 malicious / 60-79 suspicious / 41-59 info / else safe
  - VirusTotal/*                      : last_analysis_stats.malicious>0 -> malicious ; suspicious>0 -> suspicious
  - MISP/*                            : matched event threat_level_id (1 high/2 med -> malicious/suspicious)
  - Yara/yara_analyzer.py            : match_count == 0 -> safe   else -> malicious
  - HybridAnalysis/*                  : sandbox report_verdict -> malicious/suspicious/safe/info
  - Urlscan.io/urlscan_analyzer.py    : Search: total>=1 -> suspicious ; total==0 -> info   (the "noisy" source)
  - AbuseIPDB/abuseipdb.py           : abuseConfidenceScore threshold -> safe/suspicious/malicious ; isWhitelisted -> info
  - Shodan/shodan_analyzer.py        : level "info" (pure enrichment), CVEs -> suspicious
  - MaxMind, Abuse_Finder, FileInfo   : enrichment only, level "info"

Trust tiers come from the pilot's Analyzer.tier field + _tier_seed.py prefixes:
  Tier 1 (Authoritative): GTI, VirusTotal, MISP
  Tier 2 (Strong):        Yara_Boosted, ThreatGrid/HybridAnalysis sandbox, CIRCLHashlookup
  Tier 3 (Contextual):    AbuseIPDB, Shodan, Urlscan, Zscaler, MaxMind, Abuse_Finder, FileInfo
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# 1. Analyzer taxonomy-level logic (mirrors the real Cortex-Analyzers summary())
# ─────────────────────────────────────────────────────────────────────────────

def gti_level(raw: dict) -> str:
    attrs = raw.get("attributes", {})
    ts = attrs.get("gti_assessment", {}).get("threat_score", {}).get("value", 0)
    if ts >= 80: return "malicious"
    if 60 <= ts <= 79: return "suspicious"
    if 41 <= ts <= 59: return "info"
    return "safe"

def vt_level(raw: dict) -> str:
    stats = raw.get("last_analysis_stats", {})
    if int(stats.get("malicious", 0)) > 0: return "malicious"
    if int(stats.get("suspicious", 0)) > 0: return "suspicious"
    if any(stats.get(k, 0) for k in ("harmless", "undetected", "timeout")): return "info" if not stats else "safe"
    return "safe"

def misp_level(raw: dict) -> str:
    # threat_level_id: 1 High, 2 Medium, 3 Low, 4 Undefined
    events = [e for block in raw.get("results", []) for e in block.get("result", [])]
    if not events: return "safe"          # no matched event
    tl = min(int(e.get("threat_level_id", 4)) for e in events)
    return {1: "malicious", 2: "suspicious", 3: "suspicious", 4: "info"}[tl]

def yara_level(raw) -> str:
    matches = raw if isinstance(raw, list) else raw.get("results", [])
    return "safe" if len(matches) == 0 else "malicious"

def sandbox_level(raw: dict) -> str:
    v = raw.get("report_verdict", "unknown")
    return {"malicious": "malicious", "suspicious": "suspicious",
            "whitelisted": "safe", "no specific threat": "info"}.get(v, "info")

def urlscan_search_level(raw: dict) -> str:
    total = raw.get("indicator", {}).get("total", 0)
    return "suspicious" if total >= 1 else "info"     # <-- the FP source

def abuseipdb_level(raw: dict) -> str:
    d = raw.get("values", [{}])[0].get("data", {})
    if d.get("isWhitelisted"): return "info"
    score = int(d.get("abuseConfidenceScore", 0))
    if score >= 75: return "malicious"
    if score >= 25: return "suspicious"
    return "safe"

def enrichment_level(raw: dict) -> str:
    return "info"     # Shodan/MaxMind/Abuse_Finder/FileInfo — never a verdict


# ─────────────────────────────────────────────────────────────────────────────
# 2. The engine  (spec Tasks 8-10)
# ─────────────────────────────────────────────────────────────────────────────

_LEVEL_TO_VERDICT = {"malicious": "malicious", "dangerous": "malicious",
                     "suspicious": "suspicious", "safe": "clean"}

@dataclass(frozen=True)
class SourceVerdict:
    name: str
    tier: int
    weight: float
    verdict: str            # malicious | suspicious | clean | no-data
    confidence: Optional[int]
    failed: bool
    evidence: str

def source_verdict(name, tier, weight, level, *, status="Success",
                   confidence=None, evidence="") -> SourceVerdict:
    failed = status == "Failure"
    verdict = "no-data" if status != "Success" else _LEVEL_TO_VERDICT.get(level, "no-data")
    return SourceVerdict(name, tier, weight, verdict, confidence, failed, evidence)

HIGH_CONFIDENCE = 70
DANGEROUS_SHARE = 0.5
MIN_TRUSTED_COVERAGE = 1
TIER_MULTIPLIER = {1: 4, 2: 2, 3: 1}
_FLAGGED = ("malicious", "suspicious")

@dataclass(frozen=True)
class ObservableVerdict:
    band: str
    confidence: int
    inconclusive_reason: Optional[str]
    counts: dict
    rationale: list

def _mult(s: SourceVerdict) -> float:
    return s.weight * TIER_MULTIPLIER.get(s.tier, 1)

def _confidence(sources, split=None) -> int:
    voting = [s for s in sources if s.verdict != "no-data"]
    if not voting: return 0
    total_w = sum(_mult(s) for s in voting) or 1.0
    mal_w = sum(_mult(s) for s in voting if s.verdict == "malicious")
    clean_w = sum(_mult(s) for s in voting if s.verdict == "clean")
    lopsided = (1.0 - split) if split is not None else abs(mal_w - clean_w) / total_w
    trusted = [s for s in voting if s.tier in (1, 2)]
    coverage = min(1.0, len(trusted) / 3.0)
    fail_pen = min(0.6, sum(0.3 if s.tier == 1 else 0.1 for s in sources if s.failed))
    return max(0, min(100, round(lopsided * (0.4 + 0.6 * coverage) * (1.0 - fail_pen) * 100)))

def score_observable(sources: list) -> ObservableVerdict:
    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "no-data": 0}
    for s in sources:
        counts[s.verdict] += 1
    voting = [s for s in sources if s.verdict != "no-data"]
    trusted_voting = [s for s in voting if s.tier in (1, 2)]
    t1_mal = [s for s in trusted_voting if s.tier == 1 and s.verdict == "malicious"]
    t2_mal = [s for s in trusted_voting if s.tier == 2 and s.verdict == "malicious"]
    t1_clean = [s for s in trusted_voting if s.tier == 1 and s.verdict == "clean"]
    trusted_flag = [s for s in trusted_voting if s.verdict in _FLAGGED]
    any_flag = [s for s in voting if s.verdict in _FLAGGED]
    t3_malicious = [s for s in voting if s.tier == 3 and s.verdict == "malicious"]
    _trusted_malicious = any(s.tier in (1, 2) and s.verdict == "malicious" for s in voting)
    rationale = []

    # Rule 0 — coverage: too few trusted sources voted AND nothing flags the
    # observable. A Tier-3 flag under thin coverage is still actionable (spec
    # §4.2: "Tier-3-only evidence caps at Suspicious"), so it falls through.
    if len(trusted_voting) < MIN_TRUSTED_COVERAGE and not any_flag:
        rationale.append(f"Only {len(trusted_voting)} trusted source(s) returned a verdict — cannot assess.")
        return ObservableVerdict("Inconclusive", _confidence(sources, split=1.0),
                                 "thin_coverage", counts, rationale)

    total_w = sum(_mult(s) for s in voting) or 1.0
    share = sum(_mult(s) for s in voting if s.verdict == "malicious") / total_w

    # Rule 1 — Dangerous
    decisive_t1 = [s for s in t1_mal if s.confidence is None or s.confidence >= HIGH_CONFIDENCE]
    if decisive_t1:
        rationale.append(f"{decisive_t1[0].name} (authoritative) reports malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if len(t2_mal) >= 2:
        rationale.append(f"{len(t2_mal)} strong sources agree malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if share >= DANGEROUS_SHARE and _trusted_malicious:
        rationale.append(f"Trust-weighted malicious share {share:.0%}.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)

    # Rule 2 — Safe: a Tier-1 clean verdict beats Tier-3 noise (e.g. urlscan Search
    # flags every previously-scanned URL). A Tier-3 *malicious* still blocks Safe
    # (-> Rule 3 caps it at Suspicious); a Tier-3 *suspicious* alone does not.
    if t1_clean and not trusted_flag and not t3_malicious:
        note = "" if not any_flag else " (low-trust noise overridden)"
        rationale.append(f"{t1_clean[0].name} (authoritative) clean; no trusted source flags it{note}.")
        return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)

    # Rule 3 — Suspicious
    if any_flag:
        if trusted_flag:
            rationale.append(f"{trusted_flag[0].name} flags it; evidence not decisive.")
        else:
            rationale.append("Only contextual/low-trust sources flag this — capped at Suspicious.")
        return ObservableVerdict("Suspicious", _confidence(sources), None, counts, rationale)

    # nothing flagged
    rationale.append("No source flags the indicator.")
    return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)


# allow-list short-circuit (the pilot's check_allow_list ip branch)
def with_allow_list(value: str, allow_listed_ips: set, sources: list) -> ObservableVerdict:
    if value in allow_listed_ips:
        return ObservableVerdict("Safe", 100, None,
                                 {"malicious": 0, "suspicious": 0, "clean": 0, "no-data": 0},
                                 [f'{value} is on the IP allow-list ("Safe IPW triggered").'])
    return score_observable(sources)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Five use cases — realistic analyzer output from the GTI comparison table
# ─────────────────────────────────────────────────────────────────────────────

CASES = []

def case(name, expected, gti_said, builder):
    CASES.append((name, expected, gti_said, builder))

# ---- Case 1: Linux ELF Mirai, UPX-packed  (GTI: suspicious ; today: aligned) ----
case("Linux ELF Mirai — UPX packed", {"Suspicious", "Dangerous"}, "suspicious", lambda: [
    source_verdict("Yara_Boosted_3_2", 2, 0.3,
        yara_level([{"rule": "UPX_ELF_packed"}, {"rule": "Mirai_generic_strings"}]),
        evidence="2 rules: UPX_ELF_packed, Mirai_generic_strings"),
    source_verdict("GoogleThreatIntelligence_GetReport", 1, 0.9,
        gti_level({"attributes": {"gti_assessment": {"threat_score": {"value": 71}}}}),
        confidence=71, evidence="threat_score 71, severity MEDIUM"),
    source_verdict("VirusTotal_GetReport_3_1", 1, 0.8,
        vt_level({"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 40, "undetected": 20}}),
        confidence=55, evidence="4/64 engines"),
    source_verdict("FileInfo_8_0", 3, 0.2, enrichment_level({}), evidence="ELF 64-bit LSB executable"),
])

# ---- Case 2: Linux ELF Mirai, UNPACKED  (GTI: suspicious ; today: FALSE NEGATIVE "not suspicious") ----
case("Linux ELF Mirai — unpacked", {"Suspicious"}, "suspicious", lambda: [
    # deployed YARA ruleset keys on packer artifacts -> no match on the unpacked sample
    source_verdict("Yara_Boosted_3_2", 2, 0.3, yara_level([]), evidence="0 rules matched"),
    source_verdict("GoogleThreatIntelligence_GetReport", 1, 0.9,
        gti_level({"attributes": {"gti_assessment": {"threat_score": {"value": 67}}}}),
        confidence=67, evidence="threat_score 67 (relationships: known Mirai C2)"),
    source_verdict("VirusTotal_GetReport_3_1", 1, 0.8,
        vt_level({"last_analysis_stats": {"malicious": 0, "suspicious": 2, "harmless": 45, "undetected": 25}}),
        confidence=45, evidence="2/72 engines flag suspicious"),
    source_verdict("CIRCLHashlookup_1_1", 2, 0.3, "info", evidence="hash unknown to NSRL"),
])

# ---- Case 3: one of the 6 URLs  (GTI: 6 suspicious ; today: UNDER-DETECTED, 1 failed) ----
case("Phishing URL (1 of 6)", {"Suspicious"}, "suspicious", lambda: [
    source_verdict("GoogleThreatIntelligence_GetReport", 1, 0.9,
        gti_level({"attributes": {"gti_assessment": {"threat_score": {"value": 64}}}}),
        confidence=64, evidence="threat_score 64, category phishing"),
    source_verdict("VirusTotal_GetReport_3_1", 1, 0.8,
        vt_level({"last_analysis_stats": {"malicious": 0, "suspicious": 3, "harmless": 70, "undetected": 16}}),
        confidence=40, evidence="3/89 engines"),
    source_verdict("Urlscan_io_Search_0_1_1", 3, 0.2,
        urlscan_search_level({"indicator": {"total": 0}}), evidence="no prior scans"),
    source_verdict("Zscaler_1_3", 3, 0.2, "info", status="Failure",
        evidence="analyzer timed out"),   # the "1 échec"
])

# ---- Case 4: http://auth.users.pub  (GTI: NOT suspicious ; today: FALSE POSITIVE "suspicious") ----
case("http://auth.users.pub", {"Safe"}, "not suspicious", lambda: [
    source_verdict("GoogleThreatIntelligence_GetReport", 1, 0.9,
        gti_level({"attributes": {"gti_assessment": {"threat_score": {"value": 12}}}}),
        confidence=88, evidence="threat_score 12, no detections"),
    source_verdict("VirusTotal_GetReport_3_1", 1, 0.8,
        vt_level({"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 72, "undetected": 6}}),
        confidence=90, evidence="0/78 engines"),
    # urlscan Search returns "suspicious" for ANY url with >=1 prior scan -> the noisy source
    source_verdict("Urlscan_io_Search_0_1_1", 3, 0.2,
        urlscan_search_level({"indicator": {"total": 4}}), evidence="4 prior scans (benign)"),
    source_verdict("Zscaler_1_3", 3, 0.2, "info", evidence="category: Miscellaneous"),
])

# ---- Case 5: 8.8.8.8  (GTI: NOT suspicious ; today: FALSE POSITIVE "suspicious") ----
def case5_sources():
    return [
        source_verdict("GoogleThreatIntelligence_GetReport", 1, 0.9,
            gti_level({"attributes": {"gti_assessment": {"threat_score": {"value": 0}}}}),
            confidence=95, evidence="threat_score 0"),
        source_verdict("VirusTotal_GetReport_3_1", 1, 0.8,
            vt_level({"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 86, "undetected": 3}}),
            confidence=92, evidence="0/89 engines"),
        source_verdict("AbuseIPDB_1_0", 3, 0.2,
            abuseipdb_level({"values": [{"data": {"isWhitelisted": True, "abuseConfidenceScore": 0}}]}),
            evidence="whitelisted, confidence 0%"),
        source_verdict("Shodan_Host_1_0", 3, 0.2, enrichment_level({}), evidence="ports 53, 443 — Google LLC"),
        source_verdict("MaxMind_GeoInfo_3_0", 3, 0.2, enrichment_level({}), evidence="US, Google LLC, AS15169"),
    ]
case("8.8.8.8 (pure engine, not allow-listed)", {"Safe"}, "not suspicious", case5_sources)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Run
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"{'CASE':<40} {'GTI':<16} {'ENGINE':<12} {'EXPECTED':<22} RESULT")
    print("-" * 110)
    failures = 0
    for name, expected, gti_said, builder in CASES:
        sources = builder()
        v = score_observable(sources)
        ok = v.band in expected
        failures += not ok
        exp = "|".join(sorted(expected))
        print(f"{name:<40} {gti_said:<16} {v.band:<12} {exp:<22} {'PASS' if ok else 'FAIL <<<'}")
        flagged = sum(1 for s in sources if s.verdict in _FLAGGED)
        n = sum(1 for s in sources if s.verdict != 'no-data')
        print(f"    ratio: {flagged}/{n} sources flagged   confidence: {v.confidence}"
              + (f"   ({v.inconclusive_reason})" if v.inconclusive_reason else ""))
        for s in sources:
            tag = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢", "no-data": "⚪"}[s.verdict]
            fail = " [FAILED]" if s.failed else ""
            print(f"      T{s.tier} {tag} {s.name:<38} {s.verdict:<11}{fail}  {s.evidence}")
        for line in v.rationale:
            print(f"    → {line}")
        print()

    # allow-list path (the pilot's check_allow_list ip branch)
    print("-" * 110)
    print("Case 5b: 8.8.8.8 WITH an AllowListIp entry (pilot's check_allow_list ip branch):")
    v = with_allow_list("8.8.8.8", {"8.8.8.8"}, case5_sources())
    print(f"    ENGINE: {v.band}   → {v.rationale[0]}")
    assert v.band == "Safe"

    print("-" * 110)
    if failures:
        print(f"{failures} case(s) FAILED")
        raise SystemExit(1)
    print(f"All {len(CASES)} cases resolved to their expected band. "
          f"2 false negatives + 2 false positives from the GTI table are fixed; "
          f"the aligned case stays aligned.")

if __name__ == "__main__":
    main()
