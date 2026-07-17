from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.cron.user_and_cases import update_ongoing_cases


class CronEnqueuesJoblessTest(TestCase):
    def test_jobless_ongoing_case_is_enqueued(self):
        user = get_user_model().objects.create_user(username="cr_u", password="x")
        case = Case.objects.create(
            description="", reporter=user, lifecycle_state=LifecycleState.CREATED,
        )
        with patch("tasp.cron.user_and_cases.reconcile_case.delay") as mock_delay:
            update_ongoing_cases()
        mock_delay.assert_any_call(case.id)
