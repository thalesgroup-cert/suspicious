# Elastic SIEM Connector: Design

Resolves GitHub issue #405.

## Context

Analysts working in Elastic Security want Suspicious verdicts in their SIEM
without polling the Suspicious UI. Suspicious already forwards finalised
cases to TheHive and MISP through the connector framework (registry, dispatch,
delivery ledger, retries, circuit breaker, per-connector on/off). Nothing
forwards to Elastic.

Two ways in were considered: the Kibana Cases API (`POST /api/cases`) and
indexing documents into Elasticsearch. This spec takes indexing:

- A document keyed by case id is idempotent under the framework's retries
  with no extra state. Kibana Cases would need a case-to-Kibana-id mapping
  model, a migration, and create-vs-update logic.
- Detection rules, dashboards and Elastic Security Cases can all be built on
  an indexed document. The reverse is not true.
- A Kibana Cases connector can follow as a second connector if wanted.

## Goals

- Forward finalised cases at or above a configurable verdict to Elasticsearch
  as ECS documents, automatically, with no code on the Elastic side.
- Keep the SIEM consistent when an analyst changes a verdict afterwards,
  including a downgrade.
- Send summaries and IOCs only. No mail bodies, no analyzer reports.
- Off by default; no effect on any existing deployment.

## Non-goals

- No Kibana API calls (Cases, detection rules, alerts). Rules are the
  operator's to write.
- No reuse of `case_search` config or index. That connector talks to the
  internal `elasticsearch:9200` for search; this one targets an
  operator-supplied cluster. Separate settings, separate index.
- No Elasticsearch client library. Plain `requests`, so there is no client
  and server version coupling and no new dependency.
- No data stream. Data streams are append-only and cannot overwrite by `_id`.
- No new secret mechanism. `ConfigField(type="secret")` already flows through
  the Vault overlay.
- No reporter identity. The reporter's email and username stay in Suspicious.

## Architecture

New contrib connector `connectors/contrib/elastic_siem/`: `connector.py`,
`service.py` (document builder, verdict filter, HTTP), `tests/`. One new
management command, `reindex_siem`. No model, no migration.

### Config (manifest `config_schema`)

```python
ConfigField("url", type="url", required=True,
            help="Elasticsearch base URL, e.g. https://siem.internal:9200"),
ConfigField("api_key", type="secret", required=True,
            help="Elasticsearch API key (the base64 'encoded' value)."),
ConfigField("index", type="str", default="logs-suspicious.case"),
ConfigField("min_verdict", type="str", default="Suspicious",
            help="Lowest verdict forwarded: Safe, Inconclusive, Suspicious or Dangerous."),
ConfigField("verify_tls", type="bool", default=True),
ConfigField("timeout_seconds", type="int", default=10),
ConfigField("create_index", type="bool", default=True,
            help="Create the index with ECS mappings if it does not exist."),
ConfigField("ui_base_url", type="url", required=False,
            help="Suspicious UI base URL; when set, documents carry a link to the case."),
```

`enabled_by_default=False`. Events: `case_finalised`, `case_modified`.

TLS verification is on by default. An internal CA is handled with the standard
`REQUESTS_CA_BUNDLE` environment variable, no new field. `verify_tls=false` is
the explicit, visible escape hatch.

### Verdict filter

Ranks: `Safe` and `AllowListed` 0, `Inconclusive` 1, `Suspicious` 2,
`Dangerous` 3. A case is forwarded when its rank is at least the rank of
`min_verdict`. `Unchallenged` and `Failure` have no rank: they are never
forwarded and never trigger an update. An unknown `min_verdict` value raises
`ValueError` (a configuration error visible in the delivery ledger), never
a silent fallback to "forward everything".

### Hook behaviour

| Event | Case at or above `min_verdict` | Case below `min_verdict` |
|---|---|---|
| `case_finalised` | upsert the document | do nothing |
| `case_modified` | upsert the document | partial `_update` of the existing document; 404 ignored |

Upsert is `PUT {url}/{index}/_doc/{case_id}`; replays overwrite the same
document. The downgrade path is `POST {url}/{index}/_update/{case_id}` with
`{"doc": {...verdict fields...}}`. If the case was never forwarded the
document does not exist, the call returns 404, and that is success. A
downgraded case therefore never leaves a stale Dangerous in the SIEM, and a
case that was never forwarded is never created by a downgrade.

Any other non-2xx response, a timeout, or a connection error raises so the
framework records a failed `ConnectorDelivery` and retries. 401 and 403 raise
with an "authentication failed" message that never includes the key.

### Document (ECS 8.x)

One document per case, `_id` = case id. Built from the case, its mail and
`collect_case_targets`, the same walk `case_search` uses.

| Field | Source |
|---|---|
| `@timestamp` | time of indexing (UTC) |
| `event.kind` | `event` |
| `event.category` | `["email", "threat"]` |
| `event.type` | `["info"]` |
| `event.module`, `event.dataset` | `suspicious`, `suspicious.case` |
| `event.action` | the triggering event name |
| `event.id` | case id |
| `event.created` | case creation time |
| `event.risk_score` | `Case.final_score` |
| `suspicious.case_id`, `.verdict`, `.score`, `.confidence`, `.status` | case |
| `suspicious.decisive_rule` | `verdict_explanation.decisive_rule` |
| `suspicious.url` | `ui_base_url` + case path, when `ui_base_url` is set |
| `email.subject`, `email.from.address`, `email.to.address`, `email.cc.address`, `email.message_id` | the case's mail |
| `url.original` | URL IOCs |
| `file.name` | attachment and uploaded file names |
| `file.hash.md5` / `.sha1` / `.sha256` | hash IOCs and the hash of each attachment or uploaded file, by `Hash.hashtype` when recognisable |
| `related.ip`, `related.hash`, `related.hosts` | IP, hash, and domain/URL-host IOCs, for pivoting |

Values are capped at 512 characters, lists are de-duplicated, and empty fields
are omitted. A non-mail case (file, URL, IP, hash) simply has no `email.*`
fields.

### Index creation

When `create_index` is true, the first delivery checks `HEAD {url}/{index}`
and, on 404, creates it with ECS-typed mappings (`keyword` for identifiers and
IOC fields, `date`, `float`, `ip` for `related.ip`) and `dynamic: false` on
`suspicious.*`. The create request sends mappings only, no shard or replica
settings, so it also works on managed and serverless Elastic. An operator who
manages index templates sets `create_index` to false and owns the mapping.
Concurrent first deliveries that both try to create the index treat the
"already exists" response as success.

### Visibility in Elastic Security

Detection rules read the index patterns in `securitySolution:defaultIndex`
(`apm-*-transaction*`, `auditbeat-*`, `endgame-*`, `filebeat-*`, `logs-*`,
`packetbeat-*`, `winlogbeat-*`). The default index is therefore named
`logs-suspicious.case`: it matches `logs-*` and the documents are visible to
rules and the default Security data view with no Kibana change. A custom
`index` must be added to that setting, or to the rule's data view, by the
operator.

The name must not match `logs-*-*` (two dashes). That pattern is the built-in
`logs` data-stream template. Creating the index explicitly, as `create_index`
does, still yields a plain index, but with `create_index` false and no
pre-created index the first write would auto-create a data stream, which
accepts only `op_type=create` and rejects overwrite-by-id. A unit test pins the
default against both patterns, and the docs say so.

Documents become alerts only through a detection rule. The README ships a
sample custom-query rule, `event.dataset : "suspicious.case" and
suspicious.verdict : "Dangerous"`. Shipping or creating rules through the
Kibana API stays a non-goal.

### `health_check`

`GET {url}/` with the API key and a 5 s timeout. It never raises.

| Result | Status |
|---|---|
| 2xx | ok, "reachable" plus the reported version when present |
| 401 / 403 | not ok, "authentication failed" |
| other 4xx, 5xx, timeout, connection error | not ok, with detail |
| `url` or `api_key` unset | not ok, "url/api_key not configured" |
| `min_verdict` not a known verdict | not ok, names the field |

### Backfill: `reindex_siem`

`manage.py reindex_siem [--since DATE] [--min-verdict V] [--dry-run]` upserts
existing cases that meet the filter, for the first fill and for repair. It
reuses the document builder and the `CASE_RELATED` select-related set, sends
through the same HTTP helper in batches of 500 via `_bulk`, and prints
sent/skipped/failed counts. It refuses to run while the connector is disabled
or unconfigured.

## Data governance

- Only summaries and IOCs leave the platform: verdict, score, confidence,
  decisive rule, mail subject, Message-ID, sender, To and CC addresses, and IOC values.
  Mail bodies, headers, attachments' content, analyzer reports and the reporter's
  identity are never sent.
- Sender and recipient addresses and the subject are personal data in the
  email sense. The operator enabling the connector is declaring the target
  cluster trusted at the same level as the TheHive and MISP instances. Docs
  must say so plainly.
- Off by default, and it needs a URL and an API key before it does anything.
- The API key is a secret field: masked in the API, stored through Vault when
  Vault is configured, and never logged.
- Recommended API key privileges: `create_index`, `index`, `write` and
  `view_index_metadata` on the target index only, plus `monitor` (cluster) if
  the health check is wanted.

## Testing

- Verdict filter: rank table, `min_verdict` unknown raises, `Unchallenged` and
  `Failure` never forwarded.
- Document builder: mail case, file case, URL/IP/hash/domain cases; caps,
  de-duplication, omitted empties, no reporter data, `suspicious.url` only
  with `ui_base_url`; hash type mapping.
- Hook (mocked `requests`): finalised at/above threshold upserts to
  `{url}/{index}/_doc/{id}` with the `Authorization: ApiKey` header; finalised
  below threshold sends nothing; modified at/above upserts; modified below does
  a partial `_update`; `_update` 404 is success; 5xx, timeout and connection
  error raise; 401/403 raise without the key in the message.
- Index creation: created once on 404, skipped when present, skipped when
  `create_index` is false, "already exists" race treated as success.
- `health_check`: one test per row of the table above.
- Manifest: valid, off by default, `api_key` is `secret`, events are
  `case_finalised` and `case_modified`.
- `reindex_siem`: filter and `--since` honoured, batching, `--dry-run` sends
  nothing, refuses when disabled.

## Documentation to update with the change

- `Suspicious/Suspicious/connectors/README.md`: connector table row and a short
  section on the document, the filter and the data governance note.
- `docs/operations/integrations.md`: row for `elastic_siem`.
- `docs/getting-started/examples/`: example config values, including the
  API key privilege list.

## Open Questions / Follow-on Work (not in this spec)

- A Kibana Cases connector (create and update cases, comment on verdict
  changes) as a second connector, if analysts want cases rather than
  documents.
- A `campaign_updated` event feed so detected phishing campaigns reach the
  SIEM too.
- An ingest pipeline name field, if operators want to enrich on the Elastic
  side.
- A per-endpoint CA-path field, if `REQUESTS_CA_BUNDLE` proves awkward.
