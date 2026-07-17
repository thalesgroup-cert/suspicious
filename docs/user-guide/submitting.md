# Submitting

Submit an email, file, URL, IP, or hash for analysis. Submissions come from the
web UI, the REST API, or the email feeder's IMAP polling. Each submission
creates a `Case` and dispatches Cortex analyzers automatically.

## What you can submit

| Type | Notes |
|---|---|
| Email | `.eml`/`.msg`; attachments and embedded URLs are extracted and analyzed |
| File | Static + sandbox analysis (YARA, FileInfo, metadata) |
| URL | Direct single-URL submission always analyzes (bypasses the planner below) |
| IP | Reputation / metadata lookups |
| Hash | File-hash reputation lookup |

## URLs inside a reported email

A single phishing mail can carry dozens of near-identical links (tracking
variants, victim IDs, newsletter farms). To avoid flooding the case with
redundant Cortex jobs, mail-extracted URLs pass through the **URL analysis
planner** before dispatch. **No URL is ever discarded** — every concrete link
stays recorded — but only the meaningful ones are analyzed.

Each URL ends up in one of four states:

| Status | Meaning |
|---|---|
| `analyzed` | Selected and sent to Cortex |
| `reused` | Equivalent to a URL already analyzed (same case, or a fresh prior case within the reuse window); result is shared, no new Cortex job |
| `skipped` | Seen but below the per-domain cap; recorded, analyzable on demand |
| `pending` | Queued for analysis, result not yet back |

Equivalence is by **canonical key**: same scheme, host (lowercased, `www.`
stripped), path, and the *set* of query-parameter names — query *values* and
fragments are ignored. A URL whose payload lives in the query (`?url=`,
`?redirect=`, `?token=`) keeps a distinct key and is boosted by interestingness
scoring, so it is never collapsed behind benign tracking variants.

The planner is **fail-open**: any error on a given URL falls back to analyzing
it. It can be disabled globally with `url_analysis.enabled = false`
(see [Configuration](../getting-started/configuration.md)).

## Reviewing and re-analyzing URLs

In the submission detail (Investigations), URLs are grouped by registered
domain. Each group header shows the count and status chips
(`analyzed N / reused N / skipped N`), sorted by interestingness. Any `skipped`
URL has an **Analyze** button that promotes it to `pending` and dispatches
Cortex for that single URL — useful when a capped or reused link warrants a
fresh look.

See [Investigations](investigations.md) for the full case view.
