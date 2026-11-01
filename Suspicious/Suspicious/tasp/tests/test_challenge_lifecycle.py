"""Challenge flow keeps lifecycle_state authoritative (FINALIZED -> CONTESTED)."""
import logging

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.services.challenge import CaseChallengeService


class ChallengeLifecycleTest(TestCase):
    def test_challenge_finalized_case_moves_to_contested(self):
        user = get_user_model().objects.create_user(username="ch_lc_u", password="x")
        case = Case.objects.create(
            description="", reporter=user,
            lifecycle_state=LifecycleState.FINALIZED, status="Done",
        )
        CaseChallengeService(case, logging.getLogger("test")).mark_challenged()
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
        self.assertEqual(case.status, "Challenged")
        self.assertTrue(case.is_challenged)


class ChallengeLedgerTest(TestCase):
    """The reporter's proposal lands in the label ledger while ai_model is enabled."""

    def setUp(self):
        from connectors.models import ConnectorState
        self.state = ConnectorState
        user = get_user_model().objects.create_user(username="ch_ld_u", password="x")
        self.case = Case.objects.create(description="", reporter=user,
                                        lifecycle_state=LifecycleState.FINALIZED, status="Done")
        self.service = CaseChallengeService(self.case, logging.getLogger("test"))

    def _enable(self, enabled):
        self.state.objects.update_or_create(name="ai_model", defaults={"enabled": enabled})

    def test_enabled_writes_a_proposal_row(self):
        from ai_model.models import LabelRecord
        self._enable(True)
        self.service.mark_challenged(proposed="Safe", reason="newsletter")
        row = LabelRecord.objects.get()
        self.assertEqual((row.case, row.source, row.trust, row.label_class),
                         (self.case, "challenge", "proposal", "Safe"))

    def test_disabled_writes_nothing(self):
        from ai_model.models import LabelRecord
        self._enable(False)
        self.service.mark_challenged(proposed="Safe")
        self.assertFalse(LabelRecord.objects.exists())

    def test_blank_proposal_writes_nothing(self):
        from ai_model.models import LabelRecord
        self._enable(True)
        self.service.mark_challenged()
        self.assertFalse(LabelRecord.objects.exists())

    def test_a_ledger_failure_keeps_the_challenge(self):
        from unittest.mock import patch
        self._enable(True)
        with patch("ai_model.ledger.record_challenge", side_effect=RuntimeError("x")), \
                self.assertLogs("tasp.services.challenge", "WARNING") as logs:
            self.service.mark_challenged(proposed="Dangerous")
        self.case.refresh_from_db()
        self.assertTrue(self.case.is_challenged)
        self.assertEqual(self.case.lifecycle_state, LifecycleState.CONTESTED)
        self.assertIn("RuntimeError", logs.output[0])


class ChallengeLedgerDbErrorTest(TestCase):
    """A DB error inside the ledger write rolls back only its savepoint, not the caller's transaction."""

    def test_inside_a_caller_transaction(self):
        from unittest.mock import patch
        from django.db import IntegrityError, transaction
        from ai_model.models import LabelRecord
        from connectors.models import ConnectorState
        ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": True})
        user = get_user_model().objects.create_user(username="ch_db_u", password="x")
        case = Case.objects.create(description="", reporter=user,
                                   lifecycle_state=LifecycleState.FINALIZED, status="Done")
        with patch.object(LabelRecord, "_save_table", side_effect=IntegrityError("x")), \
                self.assertLogs("tasp.services.challenge", "WARNING"):
            with transaction.atomic():
                CaseChallengeService(case, logging.getLogger("test")).mark_challenged(proposed="Safe")
        case.refresh_from_db()
        self.assertTrue(case.is_challenged)
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
