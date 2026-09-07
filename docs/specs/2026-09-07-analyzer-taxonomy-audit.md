# Analyzer taxonomy audit — the other 15 keyless analyzers

**Date:** 2026-09-07
**Context:** follow-up to commit `3e6223cd` (SpamhausDBL). That fix flagged an
open question: *"Whether any of the other 15 [keyless analyzers enabled by
`deployment/scripts/enable-dev-analyzers.sh`] have the same self-reported-`info`
pattern hiding a real signal."* This is that audit.

## The pattern being hunted

`DefaultTaxonomyParser` (`score_process/scoring/cortex_analyzers/default.py`)
takes the **max taxonomy `level`** an analyzer self-reports. `sources.py` then
maps `level` → categorical verdict: `malicious`/`suspicious`/`safe` → a vote,
**anything else (`info`, missing) → `no-data` (no vote at all)**.

So an upstream analyzer that hardcodes `level = "info"` while putting the real
verdict in the taxonomy *value* or the `full` report contributes **nothing** to
scoring — a confirmed-bad indicator lands identical to a clean one.

All 15 analyzers are **Tier 3** (none match the tier-1/2 name prefixes in
`_tier_seed.py`). Engine consequences of a Tier-3 vote
(`observable_engine.score_observable`):

- Tier-3 `suspicious` or `malicious` → `any_flag` set → **Rule 3 forces the
  observable to `Suspicious`** unless a trusted source pulls it to Safe/Dangerous.
- Tier-3 `malicious` also blocks Rule 2 `Safe` and adds to the Dangerous
  `share` (but can't reach Dangerous without a trusted malicious — correct).
- Tier-3 `clean` → minor; only counts + confidence weighting.

## Verdict per analyzer

| Analyzer | Upstream `summary()` level logic | Assessment |
|---|---|---|
| **ThreatMiner_1_0** | default `suspicious`; → `safe` iff `len(results) != 0` | **BUG — worst.** Inverted. Unknown/never-seen indicator, or a failed call to its flaky API, → phantom Tier-3 `suspicious` → observable forced to **Suspicious**. A row hit → unearned `safe` vote. Systematic false-positive generator. |
| **TeamCymruMHR_1_0** | hardcoded `level = 'info'`, taxonomies emitted only when `status == "found_record"` | **BUG — signal lost.** Team Cymru's Malware Hash Registry only returns a record for AV-flagged samples. A confirmed-malware hash → `info` → `no-data`. AV `detection_pct` buried in the value. Same class as SpamhausDBL. |
| **DomainMailSPFDMARC_1_2** | dynamic: no SPF + no DMARC → `malicious`×2; one missing → `suspicious` | **Populated but over-aggressive.** Levels *are* set, so `DefaultTaxonomyParser` works — but "no DMARC record" = `malicious` is harsh (many legit small domains). Two Tier-3 `malicious` votes → blocks Safe, → Suspicious. Decision, not touched. |
| **Cyberprotect_ThreatScore_3_0** | passes through `raw['threatscore']['level']` from the vendor API | **Probably fine.** Depends on the vendor returning cortex-style level strings. If it ever returns `"high"`/numeric, `DefaultTaxonomyParser` → `info`. Can't confirm without live data. Low priority. |
| DShield_lookup_1_0 | `safe`/`suspicious`/`malicious` from `maxrisk` + threatfeed count | OK |
| CyberCrime-Tracker_1_0 | `malicious` iff `hit_count > 0` | OK |
| StopForumSpam_1_0 | `safe`/`suspicious`/`malicious` from confidence vs configured thresholds | OK |
| ClamAV_FileInfo_1_1 | `malicious` on any match, else `safe` | OK |
| Crt_sh_Transparency_Logs_1_0 | hardcoded `info` (cert count) | OK — genuinely informational, no verdict to lose |
| GoogleDNS_resolve_1_0_0 | hardcoded `info` (record count) | OK — DNS resolution is not a verdict |
| Mnemonic_pDNS_Public_3_0 | `info` for the public service (by design) | OK — passive-DNS count, no verdict |
| CIRCLHashlookup_1_1 | `safe` iff trusted, else `info` | Already has a bespoke parser (`CirclHashlookupParser`) |
| UnshortenLink_1_2 | hardcoded `info` (success/failure) | OK *as a parser* — but see "extractor" note below |
| MSDefenderOffice365_SafeLinksDecoder_1_0 | hardcoded `info` | OK *as a parser* — see "extractor" note |
| QrDecode_1_0 | hardcoded `info` (QR count) | OK *as a parser* — see "extractor" note |
| SpamhausDBL_1_0 | — | Already fixed (`3e6223cd`) |

## Fixed here

New bespoke parsers, same shape as `spamhaus_dbl.py`:

- **`contrib/threatminer.py`** — `ThreatMinerParser`. ThreatMiner has no verdict
  to give; always maps to `info` (no-data), carries the row count for the
  analyst. Kills the phantom `suspicious` vote.
- **`contrib/team_cymru_mhr.py`** — `TeamCymruMhrParser`. `status ==
  "found_record"` → `malicious` (presence in a malware hash registry is a
  positive detection); a very low `detection_pct` (single fringe engine) →
  `suspicious`; no record → `info`. Cutoff is a tuning knob.

## Not touched — needs a decision

1. **`auto_extract_artifacts: false`** in `enable-dev-analyzers.sh`. UnshortenLink,
   QrDecode and MSDefenderOffice365_SafeLinksDecoder are **extractors** — their
   entire value is the URL they surface (final hop of a short link, the URL
   inside a QR / "quishing", the real URL inside an ATP wrapper). With
   auto-extract off, Cortex never turns that into a new observable, so no
   analyzer ever runs on it. Their own `info` taxonomy is correct; the miss is
   upstream of scoring. Flipping the flag needs a check that Suspicious ingests
   Cortex-extracted artifacts into the IOC road.
2. **DomainMailSPFDMARC** severity calibration (see table). Either accept the
   upstream's aggressive mapping or add a parser that caps it at `suspicious`.
3. **Cyberprotect** — verify against `GET /api/analyzer` + a live report that
   `threatscore.level` is a cortex level string.
