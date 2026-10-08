# settings

DB-backed config: blacklists, whitelists, campaign settings.

## Allow/deny list uniqueness

The allow/deny lists have a unique constraint per target row. Importing a CSV row for a domain, IP or hash that already has an entry fails the whole import with an `IntegrityError` instead of silently creating a duplicate. Remove or fix the offending row and re-import.
