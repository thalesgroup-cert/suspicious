# settings

DB-backed config: blacklists, whitelists, campaign settings.

## Allow/deny list uniqueness

The allow/deny lists have a unique constraint per target row. Importing a CSV row for a domain, IP or hash that already has an entry fails the whole import with an `IntegrityError` instead of silently creating a duplicate. Remove or fix the offending row and re-import.

## List endpoints and change history

Editable lists (`domains_allow`, `domains_deny`, `campaign_domains_allow`, `emails_files_allow`, `ips_allow`, `filetypes_allow`) are served by `/api/settings/list/<section>/` (Admin/CERT only, paginated with `page`/`page_size`).

- `GET /api/settings/list/<section>/` rows are `{id, value, created_at, added_by}`. `added_by` is the username of whoever added the row, or `null` for read-only sections (Watcher lists, `ciso_users`). It comes from the existing `user` column, so rows added before this feature show their author too.
- `DELETE /api/settings/list/<section>/<id>/` removes the row and records who did it.
- `GET /api/settings/list/<section>/history/` returns `{id, value, action, username, created_at}` rows, `action` being `added` or `removed`, newest first, paginated. Unknown or read-only sections answer 400.

The history lives in the append-only `ListChangeLog` table, not in a status flag on the list tables, so the scoring and collection code that reads them is unaffected. Duplicates and Watcher conflicts that are skipped on create write nothing. The `username` is a snapshot: it stays readable after the account is deleted (`user` becomes `NULL`).

Only changes made through the Settings API are logged. Admin edits, CSV imports and code that writes the list tables directly leave no row. Deleting a user account cascades (the `user` foreign key of the six list tables is `CASCADE`) and removes the entries that user added, with no log row; the earlier `added` rows stay, with the username snapshot.

Limit: history starts when this version is deployed. Additions made earlier still show `added_by`, but removals made earlier were never recorded and cannot be recovered. The table is read-only in the Django admin.

## Allow-list behaviour

What an allow-list entry does at job launch, and how it interacts with the deny, Watcher and campaign lists, is described in [Allow lists](../../operations/allow-lists.md).
