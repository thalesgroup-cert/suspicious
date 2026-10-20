# Cortex XSOAR Connector: Design

## Context

The Cortex XSOAR pack (`integrations/xsoar`) lets a playbook submit an artifact
to Suspicious and wait for the verdict. That covers work that starts in XSOAR.
It does not cover a case that starts in Suspicious: a user reports a phishing
email to the feeder mailbox, the case is finalised as Dangerous, and the SOC
works in XSOAR but never hears about it unless someone opens Suspicious.

This connector closes that gap. When a case is finalised at or above a verdict
threshold, Suspicious opens an incident in XSOAR.

## Goals

- Open one XSOAR incident per finalised case at or above `min_verdict`, with the
  verdict, the rationale, the recommended action and the per-observable
  verdicts, so a playbook can start from it.
- Never open a second incident for a case, however often `case_finalised` fires.
- Never push back a case an XSOAR playbook submitted: its incident exists.
- Off by default; no effect on any existing deployment.

## Non-goals

- No incident updates. A verdict an analyst changes later (`case_modified`) is
  not pushed; the incident links to the case, which has the current verdict.
- No Generic Webhook transport. The REST API takes the fields we want
  directly, without a classifier and a mapper on the XSOAR side.
- No XSOAR SDK. Plain `requests`.
- No XSOAR content (incident type, layout, playbook, mapper). Those belong to
  the SOC's XSOAR configuration; `incident_type` names the type to use.

## Design

`connectors/contrib/xsoar/` is a built-in connector subscribed to
`case_finalised`.

**Which cases.** Rank `Safe` = `AllowListed` < `Inconclusive` < `Suspicious` <
`Dangerous`; a case is pushed at or above `min_verdict` (default `Suspicious`).
`Unchallenged` and `Failure` are never pushed. An unknown `min_verdict` raises,
so a typo cannot turn into "push everything". Cases whose `external_ref` starts
with `skip_ref_prefix` (default `xsoar:`, the prefix the pack puts on every
reference it generates) are skipped; an empty prefix turns that off.

**The incident.** `POST /incident` (XSOAR 6) or `POST /xsoar/public/v1/incident`
(XSOAR 8, with the `x-xdr-auth-id` header; selected by setting `api_key_id`):

| Field | Value |
|---|---|
| `name` | `Suspicious case #N: <verdict>` plus the mail subject, capped at 250 characters |
| `severity` | the ticket's severity: Safe 1, Inconclusive 2, Suspicious 3, Dangerous 4 |
| `type` | `incident_type` when set |
| `details` | Markdown: verdict, classification, rationale, recommended action, up to 25 observables, link to the case |
| `labels` | `Suspicious case`, `Suspicious verdict`, and `External reference` when set |
| `rawJSON` | the whole ticket payload, real (not defanged) values, for playbooks |
| `occurred` | the case's creation time |
| `createInvestigation` | `create_investigation` (default true) so the type's playbook runs |

`details` is for analysts: URLs, domains and IPs are defanged, and backticks and
pipes in untrusted text (subjects, rationale, observable values) are replaced so
they cannot break the Markdown. The data playbooks need is in `rawJSON`.

**Idempotency.** `connectors.ConnectorLink` holds one row per
(connector, case) with the remote id. The hook creates the row and calls XSOAR
inside one transaction: if the call fails the row rolls back and the framework's
retry starts clean; a second delivery for the same case waits on the unique row,
then sees the incident id and stops. The table is generic, so a later connector
that creates remote objects can reuse it.

This is at-least-once, not exactly-once: if XSOAR creates the incident but the
response is lost, the retry creates a second one. XSOAR's create call has no
idempotency key.

**Health.** `POST .../incidents/search` with a one-row filter: proves the URL,
the TLS setup and that the key is accepted. The key therefore needs read access
to incidents for the Test connection button even though pushing needs only
create. Failure details name the cause (`authentication failed (HTTP 401)`,
`unreachable: ConnectionError`) and never echo the key or the URL.

## Config (`integrations.xsoar`)

`url`, `api_key` (secret), `api_key_id`, `incident_type`, `min_verdict`,
`create_investigation`, `skip_ref_prefix`, `verify_tls`, `timeout_seconds`,
`ui_base_url`. Secrets stay in Vault or `settings.json`, like every connector.

## Not verified

The request and response shapes follow Palo Alto Networks' public API
documentation. They have not been run against a live XSOAR 6 or XSOAR 8 tenant;
the first real run should confirm the incident appears with the expected fields
and that the health probe's path is accepted.
