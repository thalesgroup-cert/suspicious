# Adding an analyzer source

Suspicious scores a case from the Cortex analyzers that run on its indicators. A new reputation or enrichment source (for example Shodan, AbuseIPDB, Hybrid Analysis or a screenshot tool such as Browserling) is mostly configuration: it needs no code to start contributing to verdicts. Code is only needed when you want richer evidence than the analyzer's own summary.

## 1. Enable the analyzer in Cortex

In Cortex, enable the analyzer for your organisation and fill in its configuration (API key, base URL). Suspicious cannot use an analyzer that is not enabled there. Test it once from the Cortex UI on a sample indicator before relying on it.

## 2. Let Suspicious pick it up

Suspicious lists Cortex's analyzers on a schedule (`sync_cortex`) and creates a row for each new one, marked active. Analyzers that disappear from Cortex are marked inactive. The sync assigns a **tier** from the analyzer's name:

| Tier | Meaning | Seeded for names starting with |
|---|---|---|
| 1 | Authoritative: its clear verdict decides | `VirusTotal`, `MISP`, `GoogleThreatIntelligence`, `GTI` |
| 2 | Strong | `AI_Mail_Analyzer`, `Yara`, `ThreatGrid`, `CIRCLHashlookup`, `Cuckoo`, `Hybrid` |
| 3 | Contextual: informs, does not decide | everything else (Shodan, AbuseIPDB, Browserling, …) |

Hybrid Analysis therefore starts at tier 2; Shodan, AbuseIPDB and Browserling start at tier 3. Change a tier or the numeric weight in **Settings → Analyzers** (or with `PATCH /api/settings/analyzers/<id>/` and a body of `{"tier": 2}` and/or `{"weight": 0.4}`), once you have seen how the source behaves. A new source is best left at tier 3 until you have compared it with real cases.

## 3. How its result is read

By default the analyzer's Cortex **summary taxonomy** is converted into a verdict: `safe` counts as a confident clean vote, `info` as context with no opinion, `suspicious` and `malicious` as findings. The report appears in the investigation with the source name, its tier, and the analyzer's own detail. If the analyzer fails, the case shows it in the failed-analyzers banner and the confidence is reduced.

Check that the analyzer's taxonomy really means what the default reading assumes. Two cases need care:

- A tool that only captures or describes (screenshots, whois) often reports `safe` for "it worked". That would count as a strong clean vote on every indicator. Such analyzers need a small parser that always answers `info`, as `Lookyloo_Screenshot` has.
- A feed whose taxonomy is always `info` contributes nothing to the verdict until a parser reads its numbers (an abuse confidence percentage, a count of open ports).

## 4. When you need a parser

Add `score_process/scoring/cortex_analyzers/contrib/<name>.py` with an `AnalyzerManifest` (`name`, the Cortex analyzer names in `cortex_names`, and the `data_types` it handles), following `urlscan.py` or `lookyloo.py`. To show facts in the investigation (country, ASN, vendor counts), add an extractor under `score_process/scoring/enrichment/`. Include tests with a real report from your Cortex.

## 5. Check before enabling in production

1. Enable the analyzer on a test Cortex, then run it over a few known cases.
2. Run `python manage.py backtest_scoring` before and after. It replays finalised cases through the engine and reports verdict changes; look closely at any case that moves between Safe and Dangerous.
3. Enable it in production Cortex, check the new analyzer in **Settings → Analyzers**, and watch the next cases for unexpected failures.

The analyzers listed on the roadmap (Shodan, AbuseIPDB, Hybrid Analysis, Browserling) are not enabled in this repository's development stack because they need accounts or API keys.
