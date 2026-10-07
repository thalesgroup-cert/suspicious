from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from connectors.models import ConnectorDelivery as D


class RedeliverCommandTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="x")

    def _case(self, *statuses, connector="misp", age=timedelta(hours=1)):
        c = Case.objects.create(description="d", reporter=self.user)
        for i, st in enumerate(statuses, 1):
            row = D.objects.create(connector=connector, event="case_finalised",
                                   case_id=c.id, status=st, attempt=i)
            D.objects.filter(pk=row.pk).update(created_at=timezone.now() - age)
        return c

    def _run(self, *args):
        with patch("connectors.management.commands.redeliver_connector.emit") as emit:
            call_command("redeliver_connector", "misp", *args, stdout=StringIO())
        return {call.args[1].id for call in emit.call_args_list}

    def test_only_cases_whose_latest_delivery_did_not_succeed(self):
        failed = self._case("failed", "failed", "failed")
        skipped = self._case("skipped")
        recovered = self._case("failed", "success")
        self._case("success")
        other = self._case("failed", connector="thehive")
        self.assertEqual(self._run(), {failed.id, skipped.id})
        self.assertNotIn(other.id, self._run())
        self.assertNotIn(recovered.id, self._run())

    def test_recent_rows_are_left_to_the_running_retry(self):
        self._case("failed", age=timedelta(seconds=30))
        self.assertEqual(self._run(), set())

    def test_since_limits_the_window(self):
        old = self._case("failed", age=timedelta(days=3))
        fresh = self._case("failed", age=timedelta(hours=1))
        self.assertEqual(self._run("--since", "1d"), {fresh.id})
        self.assertIn(old.id, self._run())

    def test_dry_run_emits_nothing(self):
        self._case("failed")
        self.assertEqual(self._run("--dry-run"), set())

    def test_unknown_connector_errors(self):
        with self.assertRaises(CommandError):
            call_command("redeliver_connector", "nope", stdout=StringIO())


class RedeliverCampaignTest(TestCase):
    """campaign_updated needs the campaign id the original event carried."""

    def setUp(self):
        self.user = User.objects.create_user("u2", password="x")

    def _failed(self, *, member):
        from case_handler.models import Campaign, CampaignMember
        case = Case.objects.create(description="d", reporter=self.user)
        row = D.objects.create(connector="thehive", event="campaign_updated", case_id=case.id,
                               status="failed", attempt=3)
        D.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(hours=1))
        campaign = Campaign.objects.create(title="c")
        if member:
            CampaignMember.objects.create(campaign=campaign, case=case)
        return case, campaign

    def _run(self):
        with patch("connectors.management.commands.redeliver_connector.emit") as emit:
            call_command("redeliver_connector", "thehive", "--event", "campaign_updated", stdout=StringIO())
        return emit.call_args_list

    def test_emits_with_the_campaign_the_case_belongs_to(self):
        case, campaign = self._failed(member=True)
        calls = self._run()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, ("campaign_updated", case))
        self.assertEqual(calls[0].kwargs, {"campaign_id": campaign.id})

    def test_a_case_with_no_campaign_is_skipped(self):
        self._failed(member=False)
        self.assertEqual(self._run(), [])
