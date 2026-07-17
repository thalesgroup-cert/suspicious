"""
Primary/replica database router.

Opt-in: the router is only effective when a "replica" alias exists in
DATABASES (configured via settings.json `database.replica`). Without it,
all reads stay on "default" and the router becomes a no-op so existing
single-DB deployments keep working unchanged.

Routing policy:
  - Reads from apps listed in REPLICA_READ_APPS → replica.
  - All other reads, all writes → default (primary).
  - Migrations only run on default; replica's schema is managed by
    MariaDB replication, never by Django.
  - Cross-DB relations are allowed because the replica is a logical
    copy of the primary — same row identities.

Replication lag considerations:
  - The replica is asynchronous. Reads may be stale by a few seconds.
  - Endpoints with their own freshness contracts (DashboardSummaryView
    is already cached for 2 minutes) are unaffected.
  - For just-written rows, callers must read from `default` explicitly
    using `Model.objects.using("default")` to avoid read-after-write
    surprises.
"""
from django.conf import settings


class PrimaryReplicaRouter:
    PRIMARY_DB = "default"
    REPLICA_DB = "replica"

    def _replica_available(self) -> bool:
        return self.REPLICA_DB in settings.DATABASES

    def _replica_apps(self):
        return getattr(settings, "REPLICA_READ_APPS", ())

    def db_for_read(self, model, **hints):
        if not self._replica_available():
            return None
        if model._meta.app_label in self._replica_apps():
            return self.REPLICA_DB
        return None

    def db_for_write(self, model, **hints):
        return self.PRIMARY_DB

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if db == self.REPLICA_DB:
            return False
        return None
