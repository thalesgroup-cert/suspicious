# Model conventions and safe-change guide

How to write a Django model in Suspicious, and how to change an existing one
without losing data. It distils the 2026-10 model audit, the Django and
MariaDB documentation, and the model layers of paperless-ngx and
mozilla/addons-server. Where a rule is a recommendation for **new** code only,
it says so: do not mass-rename or rewrite existing models to match.

Stack facts this guide relies on: Django 6.1, MariaDB (InnoDB, DYNAMIC row
format, `utf8mb4`), `mysqlclient`, tests run on SQLite.

## 1. Template for a new model

```python
from django.db import models
from django.utils.translation import gettext_lazy as _


class TimestampedModel(models.Model):
    """Proposed home: common/model_mixins.py. Uses the project's majority names
    (creation_date / last_update: 45 and 44 existing fields, against 7 and 6
    for created_at / updated_at)."""
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Verdict(models.TextChoices):
    SAFE = "Safe", _("Safe")
    DANGEROUS = "Dangerous", _("Dangerous")


class Example(TimestampedModel):
    case = models.ForeignKey("case_handler.Case", on_delete=models.CASCADE,
                             related_name="examples")        # FKs are indexed already
    kind = models.CharField(max_length=20, choices=Verdict.choices,
                            default=Verdict.SAFE)
    external_id = models.CharField(max_length=64)
    detail = models.JSONField(default=dict, blank=True)       # small, bounded JSON only

    class Meta:
        # No default ordering on a table that grows: order explicitly in queries.
        indexes = [
            models.Index(fields=["kind", "-creation_date"], name="example_kind_created_idx"),
        ]
        constraints = [
            models.UniqueConstraint(fields=["case", "external_id"], name="uniq_example_case_ext"),
            models.CheckConstraint(condition=~models.Q(external_id=""), name="example_ext_not_empty"),
        ]

    def __str__(self):
        return f"Example #{self.pk}"        # never touch a relation here: it costs a query per row
```

## 2. Rules

**Structure**
1. One abstract timestamp base, with the existing names (`creation_date`, `last_update`). New models inherit it; existing models keep their field names (a rename touches serializers, admin, queries and the frontend for no gain).
2. Use `TextChoices` for every closed vocabulary, and give the column `choices` (`Case.results_ai` has none today).
3. A model that targets "one of several" things (like `AnalyzerReport`, `CaseArtifact`) gets a `CheckConstraint` that exactly one target is set. Do not add more nullable FKs without one.
4. Large or rarely read payloads (raw tool output, screenshots, full HTML) go in a side table or object storage, not a column on a hot table. Keep inline JSON small and bounded.
5. Store a derived value with `GeneratedField(db_persist=True)` instead of computing it in Python (paperless-ngx does this for content length).
6. Cap what you index: truncate long free text before it is stored or searched (`build_document` caps at 512/4096 characters).

**Indexes and constraints**
7. Do not write `db_index=True` on a `ForeignKey`: Django already indexes it (41 redundant ones exist today).
8. Add a composite `Meta.indexes` entry when a query filters on one column and sorts on another, leading with the equality column, named explicitly. Profile with `QuerySet.explain()` first.
9. A column with a default `Meta.ordering` forces a sort on every query that doesn't clear it. Prefer explicit `order_by()`; use `.order_by()` to drop an inherited ordering for counts and `exists()`.
10. **MariaDB cannot enforce a conditional unique constraint.** `supports_partial_indexes` is `False`, so `UniqueConstraint(condition=...)` (used by paperless-ngx on PostgreSQL) is silently not created here. Use a plain unique constraint, or a generated column that is `NULL` when the rule does not apply.
11. Never mark a `TextField` unique or index it without a key length. Use a `CharField` of at most 191 characters for utf8mb4 unique/indexed values, or a prefix index (section 4).

**Queries**
12. Defer the big columns on list pages (`defer()`/`only()`), read FKs as `obj.fk_id`, and use `select_related`/`prefetch_related`. Django 6.1's `FETCH_PEERS` fetch mode batches on-demand loads and is worth trying behind a test.
13. `__str__` and properties never run queries.
14. Use `bulk_create`/`bulk_update`, and `update()`/`delete()` on querysets, for more than a handful of rows.

## 3. MariaDB specifics

- **Row format.** DYNAMIC stores a large `TEXT`/`BLOB`/`JSON` value off-page and keeps a 20-byte pointer in the row, so queries that skip the column never read it. Defer such columns; a side table mainly helps paths that select every column.
- **TextField index.** Add a prefix index in a vendor-guarded `RunPython` (`schema_editor.connection.vendor == "mysql"`), `atomic = False` (MariaDB DDL is not transactional), `ALGORITHM=INPLACE LOCK=NONE`. Example: `url_process.0005`. SQLite tests skip it.
- **Charset and index length.** `utf8mb4` is 4 bytes per character, so indexed text should stay at or under 191 characters unless it is a prefix index.
- **Collation.** The server default can be case- and accent-insensitive (`utf8mb4_uca1400_ai_ci`), so exact lookups on URLs and domains match `Café`/`cafe`. Check this before relying on equality for deduplication; set `db_collation` on a column when it must be exact.
- **Connections.** `CONN_MAX_AGE` is 600 (or unlimited), so every gunicorn worker and Celery process holds a connection. Keep `workers + celery concurrency` under `max_connections`.
- **Strict mode** (`STRICT_TRANS_TABLES`) stays on. **Replica reads** need a primary fallback on lag (addons-server `get_with_primary_fallback`).
- **Instant column adds.** MariaDB adds a nullable column or one with a constant default without rewriting the table. Prefer `db_default=` over a Python-side `default=` for a new column on a big table, so the default exists in the schema.

## 4. Changing a model without losing data

Every change follows the same four steps.

1. **Pre-flight on a copy of prod.** Run the SQL in section 6 against a restored backup, not against live data. A constraint or a unique index can fail on an old row that dev never had.
2. **Expand, switch, contract.** Add the new column or table first (nullable, or with `db_default`), write both, backfill in resumable batches, switch readers, and drop the old column in a later release after a full retention window. Never `RemoveField` or `DeleteModel` in the same release that stops using it.
3. **Review the SQL.** `python manage.py sqlmigrate <app> <n>` for every migration; a `RenameField` is data-safe but breaks a running old container, so rename only in an expand/contract pair. Run `makemigrations --check` in CI.
4. **Back up, then run off-peak.** Take a backup (`make backup-db`) before any migration that drops or rewrites; the migration must be reversible (`RunPython` with a reverse), and long index builds use `ALGORITHM=INPLACE LOCK=NONE`.

A change that needs a data decision (which road does a mixed case belong to?) is not a migration: resolve the rows first in a reviewed data fix, then add the constraint.

## 5. What can be applied to existing models

"Dev check" is what the 2026-10-07 audit measured on the dev database; it says
nothing about prod, so every row still needs the section 6 query on a prod copy.

| Change | Data risk | Dev check | Verdict |
|---|---|---|---|
| Drop the 40 redundant FK `db_index=True` | None: the schema state is identical (`makemigrations --check` reports no change); source cleanup only | n/a | Done 2026-10-07 |
| Composite indexes (`Case`, `AnalyzerReport`, `CaseAnalyzerJob` follow-ups) | None | n/a | Safe, online DDL |
| `CheckConstraint`: exactly one target on `AnalyzerReport` | Fails if any row has 0 or 2+ targets | 2,522 of 2,522 rows have exactly 1 | Done 2026-10-08 (`analyzerreport_one_target_chk`) |
| Same for `CaseArtifact` and `ObservableGroupArtifact` | Same | 124/124 and 24/24 have exactly 1 | Done 2026-10-08 (`caseartifact_one_target_chk`, `observablegroupartifact_one_target_chk`) |
| `CheckConstraint`: a group case has no mail or file road | Fails on a mixed row | 0 violations | Done 2026-10-08 (`case_group_excludes_other_roads_chk`) |
| `CheckConstraint`: exactly one road per `Case` | **Fails** on a mixed row | 1 of 202 cases (id 21) has both `fileOrMail` and `nonFileIocs` | Blocked, not wanted: a file plus its own hash is an intentional pair (97 prod cases) |
| Unique constraint on allow/deny lists (one row per domain, IP, hash) | Fails on duplicates, and on NULL targets it silently allows many | 0 duplicates, 0 NULL targets in the allow list | Done 2026-10-08 (`uniq_allowlistdomain_domain`, `uniq_denylistdomain_domain`, `uniq_campaigndomainallowlist_domain`, `uniq_allowlistip_ip`, `uniq_allowlistfile_hash`); making the FK non-null is still a second step |
| `TimestampedModel` for new models | None | n/a | Apply to new models only |
| Rename `created_at`/`updated_at` to the majority names | None to data, large to code | 13 fields | Do not do it |
| Add `choices` to `Case.results_ai` | None (choices are not a DB constraint) | n/a | Safe |
| Delete dead models (`submission_queue`, `DenyListFile`, `MailAnalyzed`) | Drops rows | 0 rows in each on dev | Done 2026-10-07: each migration refuses to run if the table has rows (`common/migration_utils.refuse_if_rows`). `profiles.APIKey` stays: its admin issues Knox API keys |
| `report_full` side table | Moves the biggest column | spec 2026-10-07 | Three-release expand/contract |
| `GeneratedField` for derived columns | None when added | n/a | Optional, use for new derived values |

## 6. Pre-flight SQL pack (run on a prod copy)

```sql
-- AnalyzerReport: expect only targets = 1
SELECT (url_id IS NOT NULL)+(domain_id IS NOT NULL)+(mail_id IS NOT NULL)+(hash_id IS NOT NULL)
     +(file_id IS NOT NULL)+(ip_id IS NOT NULL)+(mail_body_id IS NOT NULL)+(mail_header_id IS NOT NULL) AS targets,
       COUNT(*) FROM cortex_job_analyzerreport GROUP BY 1;

-- Case roads: expect 1 everywhere; list the offenders
SELECT id, fileOrMail_id, nonFileIocs_id, observable_group_id FROM case_handler_case
WHERE (fileOrMail_id IS NOT NULL)+(nonFileIocs_id IS NOT NULL)+(observable_group_id IS NOT NULL) <> 1;

-- CaseArtifact / ObservableGroupArtifact: same idea over their FK columns

-- Allow/deny duplicates (repeat per table and column)
SELECT domain_id, COUNT(*) FROM settings_allowlistdomain GROUP BY domain_id HAVING COUNT(*) > 1;
SELECT COUNT(*) FROM settings_allowlistdomain WHERE domain_id IS NULL;

-- Dead models: rows that would be dropped
SELECT 'submissionqueue', COUNT(*) FROM submission_queue_submissionqueue
UNION ALL SELECT 'apikey', COUNT(*) FROM profiles_apikey
UNION ALL SELECT 'denylistfile', COUNT(*) FROM settings_denylistfile
UNION ALL SELECT 'mailanalyzed', COUNT(*) FROM mail_feeder_mailanalyzed;
```

## 7. Suggested order
1. Redundant-index and dead-model batch (after the section 6 row counts on prod).
2. `TimestampedModel` plus the one-target `CheckConstraint`s.
3. Allow/deny unique constraints, then merge the near-identical allow/deny models.
4. `report_full` side table, then retire `CaseArtifact` or the `CaseHas*` pair.
5. `Case`: drop the duplicate `score`/`final_score`, and decide the road constraint after the data fix.

Each of 3-5 needs its own spec first.
