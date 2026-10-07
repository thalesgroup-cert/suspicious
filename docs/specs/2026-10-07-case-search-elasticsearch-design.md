# Investigation search through Elasticsearch

## Problem
`InvestigationAccessMixin.filter_case_queryset` (`api/views/investigations.py`)
answers the investigations search box with a 12-clause OR of `icontains`
across Case, reporter, mail, file, URL, IP, hash and domain tables, followed by
`.distinct()`. `icontains` cannot use an index, so on a large prod database
the query scans several tables and is slow on every keystroke.

Elasticsearch already runs in the stack (8.19.7, single node, no auth) but only
as Cortex's backing store; Suspicious does not use it.

## Goals
- Substring search over the same fields as today, answered in ES.
- Permissions, status/type/result filters, ordering and pagination stay in
  the database, unchanged.
- Search keeps working if ES is down (falls back to today's ORM search).
- No second cluster. The ES address is a setting so it can move later.

## Non-goals
- Clustering or securing the ES deployment (separate infrastructure task).
- Searching analyzer reports or mail bodies.
- Replacing the dashboard/KPI queries.

## Design

### 1. Index
One index, `suspicious-cases`, on the existing cluster (name prefixed so it
never collides with Cortex's indices). One document per case, id = case pk:

| field | source |
|---|---|
| `description` | `Case.description` |
| `reporter` | reporter email and username |
| `mail_subject` | `fileOrMail.mail.subject` |
| `file_name` | `fileOrMail.file.file_path` |
| `observables` | values of `nonFileIocs` url/ip/hash, `observable_group` artifacts (url/ip/hash/domain), and the mail's `MailArtifact` url/ip/hash/domain/address values |

Substring matching uses an `ngram` analyzer (min 3, max 20) on the text
fields plus a `keyword` sub-field for exact value hits. Queries shorter than 3
characters use the existing ORM path. Case ids stay on the existing numeric
`pk` match.

### 2. Sync: a `case_search` connector
Built on the existing connector framework (registry, delivery ledger, retries,
circuit breaker, per-connector on/off). It subscribes to `case_created`,
`case_modified` and `case_finalised`, and on each event builds the document
from the case and writes it with the case id as the ES id, so replays are
idempotent. `case_finalised` is the one that picks up observables that appear
after creation (mail artifacts, derived observables).

- Config: `integrations.elasticsearch.{url, index, timeout_seconds}` in
  `settings.json`, seeded through `seed_config` like the other integrations.
  Default URL `http://elasticsearch:9200`.
- `health_check()` calls the cluster health endpoint. Index and mapping are
  created on first use (`ensure_index`).
- Disabled by default for existing installs until the backfill has run.
- Management command `reindex_cases [--since DATE]` bulk-indexes existing
  cases (batches of 500, `bulk` API) for the first fill and for repair.

### 3. Query path
In `filter_case_queryset`, when `search` is at least 3 characters and the
connector is enabled and healthy:

1. Ask ES for matching case ids (`multi_match` over the text fields, size
   capped at 10 000, `_source: false`, request timeout 2 s).
2. Apply `queryset.filter(pk__in=ids)`. Scoping (`scoped_case_queryset`), the
   status/type/result/date filters, ordering and pagination run in the
   database as today. The `.distinct()` and the 12 joins disappear.

Fallback: any ES error, timeout or open circuit logs a warning and runs the
current ORM search unchanged. A result set that hits the 10 000 cap is treated
as "too broad" and the response keeps working with the capped ids.

### 4. Dependency
Add `elasticsearch>=8,<9` to `Suspicious/requirements.txt`. Client calls live
in the connector only; `api/views` imports a small `search_case_ids(query)`
helper from it.

## Testing
- Unit: document builder (file case, mail case, IOC group case), query
  builder, fallback when the client raises.
- Integration test against a real ES in CI (the `compose.ci.yaml` already
  starts one), covering index, search, update-on-modify, and fallback.
- Existing investigations API tests must pass unchanged with the connector
  disabled.

## Rollout
1. Deploy with the connector disabled; migrate and seed config.
2. Enable it, run `reindex_cases`, compare a sample of searches against the
   ORM results.
3. Keep the ORM path as the fallback permanently.

## Risks
- **Shared cluster:** a heavy Cortex job slows search. Mitigated by the 2 s
  timeout and the fallback; moving to a separate cluster is a config change.
- **Index drift** if an event is lost. `reindex_cases` repairs it; the
  delivery ledger shows failed events.
- **Memory:** ngram fields enlarge the index. Expected to be small at current
  case volumes; check index size after the backfill.
