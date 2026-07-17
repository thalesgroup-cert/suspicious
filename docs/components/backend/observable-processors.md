# Observable Processors

Per-observable analysis apps. Each extracts, normalises, and dispatches Cortex
analyzers for one observable type, and persists the resulting rows on the case.

| App | Observable | Responsibility |
|---|---|---|
| `domain_process` | Domain | Registered-domain extraction (`tldextract`), reputation/metadata dispatch |
| `url_process` | URL | URL parsing, the analysis planner (below), per-URL Cortex dispatch |
| `ip_process` | IP | IP reputation / metadata lookups |
| `hash_process` | Hash | File-hash reputation lookup |
| `file_process` | File | Static + sandbox analysis (YARA, FileInfo, metadata) |

## URL analysis planner (`url_process`)

URLs extracted from a reported email pass through a dispatch-time planner before
Cortex hand-off. It collapses equivalent URLs, reuses recent results across
cases, and caps per-domain volume — without ever discarding a URL. Direct
single-URL submission (`SubmitUrlView`) bypasses the planner; explicit user
intent always analyzes.

### Module

`url_process/url_utils/url_planner.py`

```python
def plan_url_analysis(case, url_instances) -> URLAnalysisPlan
    # URLAnalysisPlan(
    #     to_analyze: list[URL],
    #     to_reuse:   list[tuple[URL, AnalyzerReport]],
    #     skipped:    list[URL],
    # )
```

Pure, independently testable helpers:

- `canonical_key(url)` — lowercase host, strip leading `www.`, drop fragment,
  drop query *values* but keep the sorted set of query *key names*.
  `…/p?id=1&t=a` and `…/P?id=2&t=b` share a key; `…/p?redirect=evil` does not.
- `score_interestingness(url, *, sender_domain)` — additive, table-driven,
  clamped to `0..255`. Boosts raw-IP hosts, punycode, shorteners, userinfo,
  open-redirect query keys, suspicious TLDs, executables in path, odd ports,
  deep paths; suppresses sender-domain and bare hosts. Weights and denylists
  are settings-tunable without redeploy.
- `registered_domain(url)` — reuses `meioc.tldcache` / `URLHandler.get_domain`.

### Algorithm

1. Compute `canonical_key`, `interestingness`, `registered_domain`; persist the
   first two on the `URL` row.
2. **Within-case collapse** — group by `canonical_key`. Representative = highest
   interestingness (tie → shortest address); non-reps → `reused`, `analyzed_url`
   points at the representative.
3. **Cross-case TTL reuse** — for each representative, find the newest URL with
   the same key, status `analyzed`/`reused`, updated within `reuse_ttl_days`,
   carrying a usable `AnalyzerReport`. Hit → `reused` pointing at that prior row;
   miss → candidate.
4. **Per-domain cap** — group candidates by registered domain, sort by
   interestingness desc, take top `max_per_domain` → `pending` (`to_analyze`);
   overflow → `skipped`.
5. Return `URLAnalysisPlan(to_analyze, to_reuse, skipped)`.

A `reused` row never carries its own report; it resolves results by following
`analyzed_url`. The planner is **best-effort, fail-open** — any per-URL error
(malformed URL, `tldextract` miss, DB error) logs and treats the URL as
`to_analyze`, so coverage is never lost. It never raises into the dispatch path.

### Model fields (on `URL`)

| Field | Purpose |
|---|---|
| `canonical_key` | grouping + TTL lookup (indexed) |
| `analysis_status` | `pending` / `analyzed` / `reused` / `skipped` |
| `interestingness` | selection sort/display + audit (`0..255`) |
| `analyzed_url` | self-FK; `reused`/`skipped` rows point at the representative carrying the real report |

### On-demand re-analysis

`POST /api/submissions/<submission_id>/urls/<url_id>/analyze/`
(`IsAuthenticated, CanAccessSubmission`; non-owner → 404). Flips a `skipped` (or
stale `reused`) row to `pending` and dispatches Cortex for that one URL.
Idempotent — a no-op if already `pending`/`analyzed`. Frontend client:
`analyzeUrl(submissionId, urlId)`.

### Configuration

See `url_analysis.*` in [Configuration](../../getting-started/configuration.md)
(`enabled`, `max_per_domain`, `reuse_ttl_days`, `shortener_domains`,
`suspicious_tlds`). `enabled = false` restores analyze-all behaviour.
