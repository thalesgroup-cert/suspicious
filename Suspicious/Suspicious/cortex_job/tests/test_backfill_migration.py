from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class BackfillMigrationTest(TransactionTestCase):
    """Verify 0010_backfill_caseanalyzerjob applies cleanly + is idempotent.

    The full FK-walk correctness (Case ↔ NonFileIocs ↔ IP → CaseAnalyzerJob row)
    is verified in Task 10's manual integration smoke test against staging data.
    The unit test here checks only the no-raise + idempotency invariants, which
    are the hardest-to-recover properties under deploy/rollback failure modes.
    """

    def _executor(self):
        return MigrationExecutor(connection)

    def test_backfill_applies_on_empty_db(self):
        executor = self._executor()
        executor.migrate([("cortex_job", "0010_backfill_caseanalyzerjob")])
        # No rows expected when no Cases exist.
        new_state = executor.loader.project_state(
            [("cortex_job", "0010_backfill_caseanalyzerjob")]
        )
        CaseAnalyzerJob = new_state.apps.get_model("cortex_job", "CaseAnalyzerJob")
        self.assertEqual(CaseAnalyzerJob.objects.count(), 0)

    def test_backfill_is_idempotent(self):
        executor = self._executor()
        executor.migrate([("cortex_job", "0010_backfill_caseanalyzerjob")])
        # Re-applying should not raise nor add rows.
        executor.loader.build_graph()
        executor.migrate([("cortex_job", "0010_backfill_caseanalyzerjob")])
        new_state = executor.loader.project_state(
            [("cortex_job", "0010_backfill_caseanalyzerjob")]
        )
        CaseAnalyzerJob = new_state.apps.get_model("cortex_job", "CaseAnalyzerJob")
        self.assertEqual(CaseAnalyzerJob.objects.count(), 0)
