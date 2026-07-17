from unittest.mock import patch
from io import StringIO
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState


class HealOrphanedTest(TestCase):
    def test_enqueues_non_terminal_cases_only(self):
        user = get_user_model().objects.create_user(username="hl_u", password="x")
        ongoing = Case.objects.create(description="", reporter=user,
                                      lifecycle_state=LifecycleState.CREATED)
        Case.objects.create(description="", reporter=user,
                            lifecycle_state=LifecycleState.FINALIZED)
        with patch("case_handler.management.commands.heal_orphaned_cases."
                   "reconcile_case.delay") as mock_delay:
            call_command("heal_orphaned_cases", stdout=StringIO())
        mock_delay.assert_called_once_with(ongoing.id)
