# Management commands

Maintenance commands run inside the backend container, from `Suspicious/Suspicious/`:

```bash
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py <command> [options]"
```

or `cd deployment && make shell`, then `python manage.py <command>`. Every command
here is idempotent unless noted. Commands marked dry-run by default change nothing
until you pass `--apply`; the others take `--dry-run`.

Other commands are documented with their feature: `redeliver_connector`,
`reindex_cases` and `reindex_siem` ([connectors](../components/backend/connectors.md)),
`regenerate_mail_previews` ([deploy](../operations/deploy.md)), and the `ai_model_*`
commands ([ai_model](../components/backend/ai_model.md)).

## Backfills after an upgrade

These populate display-only fields on historical rows. None of them re-scores a case.

### backfill_enrichment

App `score_process`. Extracts `AnalyzerReport.enrichment` for `Success` reports that
have none.

| Option | Meaning |
|---|---|
| `--dry-run` | Count what would be written, write nothing |
| `--limit N` | Stop after N reports |

Prints `scanned X, wrote Y enrichment rows` (`would write` with `--dry-run`).

### backfill_screenshots

App `score_process`. For `Success` reports of the Lookyloo and urlscan analyzers with
no `screenshot_key`, captures the screenshot and stores it. A failed store is reported
on stderr and skipped.

| Option | Meaning |
|---|---|
| `--dry-run` | Capture but do not store; prints `would store N` |
| `--limit N` | Stop after N reports |

### backfill_verdict_explanation

App `score_process`. Fills `Case.verdict_explanation` for finalised cases that have
none (created before the verdict-explanation feature). It composes a generic
explanation (decisive rule `unknown`) from the stored analyzer reports and keeps the
case's stored rationale as the analyst text. It does not re-run the scoring engine.

| Option | Meaning |
|---|---|
| `--dry-run` | Count only |
| `--limit N` | Stop after N cases |

### dedupe_verdict_explanation_sources

App `score_process`. Repairs `verdict_explanation.sources` on cases where a re-analysis
left one source row per historical run instead of one per analyzer and target. It
keeps the stored band, confidence and decisive rule and rebuilds only the source list
and the text that depends on its size. A case is changed only when deduplication
shortens the list. Multi-observable IOC-group cases are never touched: their ids are
printed for manual review.

| Option | Meaning |
|---|---|
| `--dry-run` | Print the `old -> new` source counts, write nothing |
| `--limit N` | Stop after N cases |
| `--case-id ID` | Repair one case only |

## Data clean-up

### purge_mail_previews

App `mail_feeder`. Deletes objects from the `mail-previews` bucket by age and/or size.
It refuses to run without at least one criterion. `Mail.preview_object_key` is left
alone: a deleted preview is rendered again the next time someone opens the mail. The
daily beat entry `purge-old-mail-previews` already does the age-only sweep (90 days);
use this command for oversized recent previews.

| Option | Meaning |
|---|---|
| `--older-than-days N` | Objects older than N days |
| `--min-size-mb X` | Objects at least X MB |
| `--dry-run` | Report what would be deleted |

When both criteria are given, an object matching either one is deleted.

### relink_default_reporter

App `mail_feeder`. Emailed submissions from a sender not recognised as a company
address were attributed to the shared mailbox user. Once the sender's domain is
recognised, this command sets `Case.reporter` and `MailInfo.user` to the real user
(created if needed) for cases of the default reporter whose `Mail.reportedBy` is now a
company address. Notifications already sent to the shared mailbox are not re-sent.
Dry run by default.

| Option | Meaning |
|---|---|
| `--apply` | Write the changes |

Prints moved, skipped (not a company address) and failed counts, then the top ten
sender domains.

### misp_purge_company_iocs

App `connectors`. Lists, and with `--apply` removes, company-linked attributes and
objects already pushed to a MISP event, from before the push filters kept company
addresses, domains and links out. It refuses to run when no company domains are
configured (Watcher legit list or own domains). Deletions are MISP soft deletes that
synchronised instances pick up; copies already pulled elsewhere cannot be recalled.
Dry run by default.

| Option | Meaning |
|---|---|
| `--instance secondary\|primary` | MISP instance to scan (default `secondary`, where the monthly event lives) |
| `--event NAME` | Event info to scan (default this month's MalSpam event) |
| `--event-id ID` | Scan this event id instead of looking one up by name |
| `--apply` | Delete or rewrite what is listed |

A name that matches several events needs `--event-id`.

## Checks

### score_accuracy

App `score_process`. Read-only. Runs the observable scoring engine over the labelled
fixtures in `score_process/scoring/fixtures/labelled_cases/` (each has an
`expected_band`), prints one line per fixture (expected band, got band, `aligned`,
`FALSE POSITIVE` or `FALSE NEGATIVE`) and a tally. Exits with status 1 on any false
positive or false negative, so it can gate CI after a change to the scoring engine.
No options.
